/*
 * passthru.c
 * (C) 2019, all rights reserved,
 *
 * This file is part of WinDivert.
 *
 * WinDivert is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * WinDivert is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/*
 * DESCRIPTION:
 * This program does nothing except divert packets and re-inject them.  This is
 * useful for performance testing.
 *
 * usage: passthru.exe [windivert-filter] [num-threads] [batch-size] [priority]
 */

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "windivert.h"

#define MTU 1500

typedef struct
{
    HANDLE handle;
    int batch;
} CONFIG, *PCONFIG;

static DWORD passthru(LPVOID arg);

/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
    const char *filter = "outbound && !loopback && ip && tcp.DstPort == 443";
    int threads = 1, batch = 1, priority = 0;
    int i;
    HANDLE handle, thread;
    CONFIG config;

    if (argc > 5)
    {
        fprintf(stderr, "usage: %s [filter] [num-threads] [batch-size] "
            "[priority]\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    if (argc >= 2)
    {
        filter = argv[1];
    }
    if (argc >= 3)
    {
        threads = atoi(argv[2]);
        if (threads < 1 || threads > 64)
        {
            fprintf(stderr, "error: invalid number of threads\n");
            exit(EXIT_FAILURE);
        }
    }
    if (argc >= 4)
    {
        batch = atoi(argv[3]);
        if (batch <= 0 || batch > WINDIVERT_BATCH_MAX)
        {
            fprintf(stderr, "error: invalid batch size\n");
            exit(EXIT_FAILURE);
        }
    }
    if (argc >= 5)
    {
        priority = atoi(argv[4]);
        if (priority < WINDIVERT_PRIORITY_LOWEST ||
            priority > WINDIVERT_PRIORITY_HIGHEST)
        {
            fprintf(stderr, "error: invalid priority value\n");
            exit(EXIT_FAILURE);
        }
    }

    // Divert traffic matching the filter:
    handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, (INT16)priority,
        0);
    if (handle == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_INVALID_PARAMETER)
        {
            fprintf(stderr, "error: filter syntax error\n");
            exit(EXIT_FAILURE);
        }
        fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    // Start the threads
    config.handle = handle;
    config.batch = batch;
    for (i = 1; i < threads; i++)
    {
        thread = CreateThread(NULL, 1, (LPTHREAD_START_ROUTINE)passthru,
            (LPVOID)&config, 0, NULL);
        if (thread == NULL)
        {
            fprintf(stderr, "error: failed to start passthru thread (%d)\n",
                GetLastError());
            exit(EXIT_FAILURE);
        }
    }

    // Main thread:
    passthru((LPVOID)&config);

    return 0;
}

// Passthru thread.
static DWORD passthru(LPVOID arg)
{
    UINT8 *packet;
    UINT packet_len, recv_len, addr_len;
    WINDIVERT_ADDRESS *addr;
    PCONFIG config = (PCONFIG)arg;
    HANDLE handle;
    int batch;

    handle = config->handle;
    batch = config->batch;

    packet_len = batch * MTU;
    packet_len =
        (packet_len < WINDIVERT_MTU_MAX? WINDIVERT_MTU_MAX: packet_len);
    packet = (UINT8 *)malloc(packet_len);
    addr = (WINDIVERT_ADDRESS *)malloc(batch * sizeof(WINDIVERT_ADDRESS));
    if (packet == NULL || addr == NULL)
    {
        fprintf(stderr, "error: failed to allocate buffer (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    static int count;
    char buf[64];
    HANDLE fd;
    DWORD dwMode;

    sprintf(buf, "\\\\.\\pipe\\levent-%d",0);
    printf("creating named pipe: %s\n", buf);

    /* Create a duplex pipe which will behave like a socket pair */
    fd = CreateNamedPipe(buf, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES, 4096 * sizeof(TCHAR), 4096 * sizeof(TCHAR), 0, NULL);
    if (fd == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "error: failed to create pipe (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    //w, err : = syscall.CreateFile(syscall.StringToUTF16Ptr("nonblock_test.txt"), syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ, nil, syscall.CREATE_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL | syscall.FILE_FLAG_OVERLAPPED, 0)
    // Connect the client end of the pipe
    /*
    HANDLE clientFd = CreateFile(
        buf,   // pipe name 
        GENERIC_READ |  // read and write access 
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, // no sharing 
        NULL,           // default security attributes
        OPEN_EXISTING,  // opens existing pipe 
        FILE_FLAG_OVERLAPPED,              // default attributes 
        NULL);
    if (clientFd == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "error: failed to connect client end of pipe (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    //sv[0] = (int)fd;

    //fd = CreateFile(buf, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    //if (fd == INVALID_HANDLE_VALUE)
    //    return (-1);
    //dwMode = PIPE_NOWAIT;
    //SetNamedPipeHandleState(fd, &dwMode, NULL, NULL);
    //sv[1] = (int)fd;

    // Open process and get process handle.
    DWORD processId = 12244;
    */
    //HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, TRUE /* inherit handle (TODO: not required for this fd?) */, processId);
    //if (pHandle == INVALID_HANDLE_VALUE) {
    //    fprintf(stderr, "error: failed to open process (%d)\n",
    //        GetLastError());
    //    exit(EXIT_FAILURE);
    //}

    // Translate file descriptor.
    //HANDLE fdDup;
    //if (!DuplicateHandle(GetCurrentProcess(), clientFd, pHandle, &fdDup, DUPLICATE_SAME_ACCESS, TRUE /* inherit handle */,
    //    DUPLICATE_SAME_ACCESS /* TODO: not required? */)) {
    //    fprintf(stderr, "error: failed to duplicate handle (%d)\n",
    //        GetLastError());
    //    exit(EXIT_FAILURE);
    //}
    //printf("Duplicate handle fd: %d\n", (long long)fdDup);

    DWORD subprocessPID;
    printf("Enter Psiphon subprocess pid: ");
    scanf("%lld", &subprocessPID);
    printf("Subprocess pid %lld\n", subprocessPID);

    printf("Connecting pipe\n");
    BOOL fConnected = FALSE;


    OVERLAPPED cOverlap;
    HANDLE cEvent = CreateEvent(
        NULL,    // default security attribute 
        TRUE,    // manual-reset event 
        TRUE,    // initial state = signaled 
        NULL);   // unnamed event object 
    cOverlap.hEvent = cEvent;

    fConnected = ConnectNamedPipe(fd, &cOverlap) ?
        TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
    if (!fConnected) {
        printf("WaitForSingleObject\n");
        DWORD r = WaitForSingleObject(cOverlap.hEvent, INFINITE);
        if (r != WAIT_OBJECT_0) {
            fprintf(stderr, "error: client did not connect (%d)\n",
                GetLastError());
            exit(EXIT_FAILURE);
        }
    }
    printf("Pipe connected\n");

    // Main loop:
    while (TRUE)
    {
        // TODO/miro: need to do reads and writes concurrently

        // Read a matching packet.
        addr_len = batch * sizeof(WINDIVERT_ADDRESS);
        if (!WinDivertRecvEx(handle, packet, packet_len, &recv_len, 0,
                addr, &addr_len, NULL))
        {
            fprintf(stderr, "warning: failed to read packet (%d)\n",
                GetLastError());
            continue;
        }

        printf("Got packet from pid %lld of length %d\n", addr->Socket.ProcessId, recv_len);

        printf("Writing file\n");
        DWORD num_written = 0;
        OVERLAPPED wOverlap;
        HANDLE hEvent = CreateEvent(
            NULL,    // default security attribute 
            TRUE,    // manual-reset event 
            TRUE,    // initial state = signaled 
            NULL);   // unnamed event object 
        wOverlap.hEvent = hEvent;

        if (!WriteFile(fd, packet, recv_len, &num_written, &wOverlap) && GetLastError() != ERROR_IO_PENDING) {
            // (536) ERR_PIPE_LISTENING 
            // Waiting for a process to open the other end of the pipe.
            fprintf(stderr, "error: failed to write pipe (%d)\n",
                GetLastError());
            //exit(EXIT_FAILURE);
        }

        printf("Write: WaitForSingleObject\n");
        DWORD r = WaitForSingleObject(wOverlap.hEvent, INFINITE);
        if (r != WAIT_OBJECT_0) {
            fprintf(stderr, "error: write failed (%d)\n",
                GetLastError());
            exit(EXIT_FAILURE);
        }

        if (wOverlap.InternalHigh != recv_len) {
            fprintf(stderr, "error: failed to write all packet bytes to pipe (%d/%d bytes written)\n",
                wOverlap.InternalHigh, recv_len);
            exit(EXIT_FAILURE);
        }

        printf("Reading file..\n");

        OVERLAPPED rOverlap;
        HANDLE rEvent = CreateEvent(
            NULL,    // default security attribute 
            TRUE,    // manual-reset event 
            TRUE,    // initial state = signaled 
            NULL);   // unnamed event object 
        rOverlap.hEvent = hEvent;
        if (!ReadFile(fd, packet, packet_len, &recv_len, &rOverlap) && GetLastError() != ERROR_IO_PENDING) {
            fprintf(stderr, "error: failed to read bytes from pipe (%d)\n",
                GetLastError());
            //exit(EXIT_FAILURE);
        }
        printf("Read: WaitForSingleObject\n");
        r = WaitForSingleObject(rOverlap.hEvent, 100);
        if (r != WAIT_OBJECT_0 && r != WAIT_TIMEOUT) {
            fprintf(stderr, "error: read failed (%d) r %d\n",
                GetLastError(), r);
            //exit(EXIT_FAILURE);
        }
        if (r == WAIT_TIMEOUT) {
            printf("No new packets, continuing...\n");
            continue;
        }
        printf("Read a packet\n");
        exit(EXIT_FAILURE);
        //continue;

        printf("Injecting packet\n");

        // Re-inject the matching packet.
        if (!WinDivertSendEx(handle, packet, recv_len, NULL, 0, addr,
                addr_len, NULL))
        {
            fprintf(stderr, "warning: failed to reinject packet (%d)\n",
                GetLastError());
        }
    }
}
