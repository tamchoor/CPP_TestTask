#include <sys/types.h>
#include <sys/socket.h>
#include <iostream>

#include <netinet/in.h>
#include <libc.h>


// #define START		1
// #define STOP		2

char *scaner(char *path);

struct Client
{
	int sock;
	// int registrFlag = 0;
	char message[1024];
	int bytes_read;
};

// int	isThisStartMess(char *message)
// {
// 	std::cout << message << "= message\n";
// 	if (strcmp(message, "START") == 0)
// 		return 0;
// 	return 1;
// }

// int	isThisStopMess(char *message)
// {
// 	if (strcmp(message, "STOP") == 0)
// 		return 0;
// 	return 1;
// }

// void	checkClientMessage(Client *client)
// {
// 	if (isThisStopMess(client->message) == 0)
// 			client->registrFlag = STOP;
// 	if (client->registrFlag == 0)
// 	{
// 		// std::cout << "client.registrFlag check\n";
// 		if (isThisStartMess(client->message) == 0)
// 		{
// 			// std::cout << client->registrFlag << "= change client.registrFlag\n";
// 			client->registrFlag = START;
// 		}
// 		else
// 		{
// 			BOOST_LOG_TRIVIAL(error) << "Сообщение о нарушении протокола взаимодействия.";
// 		}
// 	}
// 	else if (client->registrFlag == 1)
// 	{
// 		BOOST_LOG_TRIVIAL(trace) << "A trace message";
// 	}
// 	// if (isThisStopMess(client->message) == 0)
// 	// 		client->registrFlag = STOP;
// }

int main()
{
	int			listener;
	struct		sockaddr_in addr;
	Client		client;

	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0)
    {
        perror("socket");
        exit(1);
    }

	addr.sin_family = AF_INET;
    addr.sin_port = htons(3425);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        exit(2);
    }
	listen(listener, 1);

	client.sock = accept(listener, NULL, NULL);
	if(client.sock < 0)
	{
		perror("accept");
		exit(3);
	}
    // while(client.registrFlag != STOP)
    // {
	char *scanerRes = NULL;
	client.bytes_read = recv(client.sock, client.message, 1024, 0);
	if (client.bytes_read > 0)
	{
		client.message[client.bytes_read] = '\0';
		// write(1, "PATH TO DIR IN SERVIS == |||", 29);
		// write(1, client.message, strlen(client.message));
		// write(1, "|||\n", 4);
		// printf("read bytes = %d",client.bytes_read );
		scanerRes = scaner(client.message);
		// checkClientMessage(&client);
	}
	send(client.sock, scanerRes, strlen(scanerRes), 0);
	// write(1, scanerRes, strlen(scanerRes));
	free(scanerRes);
	// }
	std::cout << "STOP and close\n";
	close(client.sock);
	return 0;
}
