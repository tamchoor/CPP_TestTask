#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <libc.h>
#include <iostream> 


int main(int argc, char **argv)
{
	unsigned int		maxLen = 1024;
	char				message[1024];
    int					sock;
    struct				sockaddr_in addr;

    if (argc == 2)
    {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if(sock < 0)
        {
            perror("socket");
            exit(1);
        }
        addr.sin_family = AF_INET;
        addr.sin_port = htons(3425);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
            perror("connect");
            exit(2);
        }
        // while (1)
        // {
        // char *newstr = strdup(argv[1]);
        send(sock, argv[1], strlen(argv[1]), 0);
        int bytes_read = recv(sock, message, maxLen, 0);
        if (bytes_read > 0)
        {
            write(1, message, strlen(message));
        }
                // if (strcmp(message, "STOP") == 0)
                //     break ;
        // }
        close(sock);
    }
    else 
    {
        write(1, "For call program use ./scan_util path_to_directory\n", 51);
    }
	return 0;
}
