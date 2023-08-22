/*
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see <https://www.gnu.org/licenses/>. 
 */
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdlib.h>

static void set_dtr(int fd, int val);
static void dtr_hup(int fd, int hup_time);

void set_dtr(int fd, int val)
{
    int flags = 0;

    ioctl(fd, TIOCMGET, &flags);
    if (val != 0)
    {
        flags |= TIOCM_DTR;
    }
    else
    {
        flags &= ~TIOCM_DTR;
    }

    ioctl(fd, TIOCMSET, &flags);
}

void dtr_hup(int fd, int hup_time)
{
    tcflush(fd, TCIOFLUSH);

    set_dtr(fd, 0);
    sleep(2);
    set_dtr(fd, 1);
}

int main(int argc, char** argv)
{
    int hup_time = 2;

    char c = 0;
    while ((c = getopt(argc, argv, "t:")) != -1)
    {
        switch(c)
        {
        case 't':
            hup_time = atoi(optarg);
            break;
        }
    }

    int fd;
    fd = open(argv[optind], O_RDWR | O_NOCTTY);
    if (fd < 0)
    {
        return -1;
    }

    dtr_hup(fd, hup_time);
    close(fd);

    return 0;
}