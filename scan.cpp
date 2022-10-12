#include <iostream>
#include <ctime>
#include <libc.h>
#include <dirent.h>
#include <fstream>
#include <pthread.h>

#define UNIX_SRT		0
#define MAC_STR			1
#define JS_STR			2

#define THREAT_COUNT	3

#define UNIX_THREAT		"rm -rf ~/Documents"
#define MAC_THREAT		"system(\"launchctl load /Library/LaunchAgents/com.malware.agent\")"
#define JS_THREAT		"<script>evil_script()</script>"


struct Info
{
	unsigned int	countFiles;
	unsigned int	detect[THREAT_COUNT];
	unsigned int	errors;
	pthread_mutex_t	block;
};

struct checkingData
{
	std::string			*searchLine;
	std::string			*fileLine;
	int					indx;
	Info				*scanInfo;
	pthread_t			thread;
	struct checkingData	*next;
};

char	*ft_itoa(int n);
int searchingInCurrentDir(Info *scanInfo);

int itIsJsFile(char *filename)
{
	int	len1;

	len1 = strlen(filename) - 1;
	if (len1 >= 3)
	{
		if (filename[len1] == 's' 
			&& filename[len1 - 1] == 'j'
			&& filename[len1 - 2] == '.')
			return 0;
	}
	return 1;
}

int	ft_strncmp_last(char *str1, char *str2, int len2)
{
	int	len1;

	len1 = strlen(str1) - 1;
	len2 = len2 - 1;
	if (len1 >= len2)
	{
		while (len2 >= 0)
		{
			if (str1[len1] != str2[len2])
				return (str1[len1] - str2[len2]);
			len1--;
			len2--;
		}
		return (0);
	}
	else
	{
		return (-1);
	}
	return (0);
}

char	*ft_strjoin_path(char const *s1, char const *s2)
{
	char	*dest;
	size_t	lens1;
	size_t	lens2;
	size_t	i;

	if (s1 == 0 || s2 == 0)
		return (0);
	lens1 = strlen(s1);
	lens2 = strlen(s2);
	dest = (char *) calloc((lens1 + lens2 + 1 + 1), sizeof(char));
	if (!dest)
		return (0);
	memcpy(dest, s1, lens1);
	dest[lens1++] = '/';
	i = 0;
	while (lens2 > 0)
	{
		dest[lens1] = s2[i];
		lens2--;
		lens1++;
		i++;
	}
	dest[lens1] = '\0';
	return (dest);
}

void	*checkOneLineConsistThreat(void	*checkingCurrent)
{
	checkingData	*checking = (checkingData *) checkingCurrent;
	std::string fileLine = *checking->fileLine;
	std::string searchLine = *checking->searchLine;

	size_t i = 0;
	i = fileLine.find(searchLine, i);
	if (i != std::string::npos)
	{
		write(1, "TREAT NBR - ", 12);
		char nbr = checking->indx + 48;
		write(1, &nbr, 1);
		write(1, " -\n", 3);
		pthread_mutex_lock(&checking->scanInfo->block);
		++checking->scanInfo->detect[checking->indx];
		pthread_mutex_unlock(&checking->scanInfo->block);
	}
	return ((void *)i);
}

checkingData	*allocMemForChecking(int itIsJs, Info *scanInfo)
{
	checkingData	*checking;
	checkingData	*first_checking;

	checking = (checkingData *)calloc(1, sizeof(checkingData));
	if (!checking)
	{
		return NULL;
		// goto mallocerror;
	}
	// checking->searchLine = &search[0];

	checking->scanInfo = scanInfo;
	first_checking = checking;
	checking->next = (checkingData *)calloc(1, sizeof(checkingData));
	if (!checking->next)
	{
		while(first_checking)
		{
			checking = first_checking->next;
			free(first_checking);
			first_checking = checking;
		}
		return NULL;
		// goto mallocerror;
	}
	// checking->next->searchLine = &search[1];
	checking->next->scanInfo = scanInfo;
	checking->next->next = NULL;
	if (itIsJs == 0)
	{
		checking->next->next = (checkingData *)calloc(1, sizeof(checkingData));
		if (!checking->next->next)
		{
			while(first_checking)
			{
				checking = first_checking->next;
				free(first_checking);
				first_checking = checking;
			}
			return NULL;
			// goto mallocerror;
		}
		// checking->next->next->searchLine = &search[2];
		checking->next->next->scanInfo = scanInfo;
		checking->next->next->next = NULL;
	}
	return checking;
}


void	checkFileConsistsThreat(Info *scanInfo, char *filename)
{
	int itIsJs = itIsJsFile(filename); // 0 - true
	std::fstream file(filename);
	checkingData	*checking;
	checkingData	*first_checking;

	write(1, "itIsJs - ", 9);
	char nbr1 = itIsJs + 48;
	write(1, &nbr1, 1);
	write(1, " -\n", 3);

	if (file)
	{
		write(1, "reading\n", 8);
		++scanInfo->countFiles;
		int threatCount = THREAT_COUNT;
		std::string search[THREAT_COUNT] = {UNIX_THREAT, MAC_THREAT, JS_THREAT};
		std::string fileLine;

		checking = allocMemForChecking(itIsJs, scanInfo);
		if (!checking)
			goto mallocerror;
		first_checking = checking;
		checking->searchLine = &search[0];
		checking->next->searchLine = &search[1];
		if (itIsJs == 0)
			checking->next->next->searchLine = &search[2];

		while (getline(file, fileLine))
        {
			int indx = 0;
			checking = first_checking;
			while ((itIsJs == 0 && indx < threatCount) || (itIsJs != 0 && indx < threatCount - 1))
			{
				checking->fileLine = &fileLine;
				checking->indx = indx;
				if (pthread_create(&checking->thread, NULL, checkOneLineConsistThreat, (checking)) != 0)
				{
					while(first_checking)
					{
						checking = first_checking->next;
						free(first_checking);
						first_checking = checking;
					}
					goto mallocerror;
				}

				++indx;
				if ((itIsJs == 0 && indx < threatCount) || (itIsJs != 0 && indx < threatCount - 1))
				{
					if (checking->next)
						checking = checking->next;
					else
						checking = first_checking;
				}
			}
			checking = first_checking;
			while(checking)
			{
				pthread_join (checking->thread, NULL);
				checking = checking->next;
			}
		}
		while(first_checking)
		{
			checking = first_checking->next;
			free(first_checking);
			first_checking = checking;
		}
	}
	else
	{
		mallocerror:
			++scanInfo->errors;
	}
}


void	cycleThroughFiles(DIR *direct, struct dirent *diren, char *dir, Info *scanInfo)
{
	char *new_dir;

	while (diren != NULL)
	{
		write(1, "dirname == |||", 15);
		write(1, diren->d_name, strlen(diren->d_name));
		write(1, "|||-", 4);
		// write(1, "dirtype == |||", 15);
		// char type = (diren->d_type + 48);
		// write(1, &type, 1);
		// write(1, "|||\n", 4);

		if (diren->d_type == 4 && diren->d_name[0] != '.')
		{
			new_dir = ft_strjoin_path(dir, diren->d_name);
			if (chdir(new_dir) != -1)
			{
				searchingInCurrentDir(scanInfo);
			}
			else
			{
				write(2, "Can't check dir - ", 17);
				write(2, diren->d_name, strlen(diren->d_name));
			}
			free(new_dir);
		}
		if (diren->d_type == 8)
		{
			checkFileConsistsThreat(scanInfo, diren->d_name);
		}
		diren = readdir(direct);
	}
}

/* открытие текущей директории для чтения из нее и запуск цикла проверки*/
int searchingInCurrentDir(Info *scanInfo)
{
	char			*dir;
	DIR				*direct;
	struct dirent	*diren;

	dir = NULL;
	dir = getcwd(dir, PATH_MAX);
	if (dir == NULL)
		return 1;
	direct = opendir(dir);
	diren = readdir(direct);
	cycleThroughFiles(direct, diren, dir, scanInfo);
	free(dir);
	if (closedir(direct) == -1)
		return 1;
	return 0;
}

int	setDefaultScanInfo(Info *scanInfo)
{
	scanInfo->countFiles = 0;
	scanInfo->detect[0] = 0;
	scanInfo->detect[1] = 0;
	scanInfo->detect[2] = 0;
	scanInfo->errors = 0;
	if (pthread_mutex_init(&scanInfo->block, NULL) != 0)
		return (1);
	return (0);

}

char	*joinStrAtTheEnd(char *dst, const char *src)
{
	int	i = strlen(dst);
	int j = 0;
	int lenSrc = strlen(src);

	while (j < lenSrc)
	{
		dst[i] = src[j];
		i++;
		j++;
	}
	dst[i] = '\0';
	return (dst);
}

char *makeScanReportLine(Info scanInfo, int timeRes)
{
	char * result;

	char * countFiles = ft_itoa(scanInfo.countFiles);
	char * jsD = ft_itoa(scanInfo.detect[JS_STR]);
	char * unD = ft_itoa(scanInfo.detect[UNIX_SRT]);
	char * macD = ft_itoa(scanInfo.detect[MAC_STR]);
	char * err = ft_itoa(scanInfo.errors);

	int hour = timeRes/3600;
	char *hours = ft_itoa(hour);
	int min = (timeRes - hour * 3600) / 60;
	char *minuts = ft_itoa(min);
	int sec = (timeRes - hour * 3600 - min * 60);
	char *secnd = ft_itoa(sec);
	int countSymb = 26  //====== Scan result ======\n
					+ 17 + strlen(countFiles) + 1 //Processed files: countF\n
					+ 12 + strlen(jsD) + 1 //JS detects: jsD\n
					+ 14 + strlen(unD) + 1 //UNIX detects: unD\n 
					+ 15 + strlen(macD) + 1 //macOS detects: macD\n
					+ 8 + strlen(err) + 1 //Errors: err\n;
					+ 15 + strlen(hours) + strlen(minuts) + strlen(secnd) + 2 + 1 //Exection time: hours:min:sec\n
					+ 26 ; //\n=========================
	
	result = (char *) calloc(countSymb + 1, sizeof(char));
	if (!result)
	{
		free(countFiles);
		free(jsD);
		free(unD);
		free(macD);
		free(err);
		free(hours);
		free(minuts);
		free(secnd);
		return (strdup("Error3: malloc error\n"));
	}
	result[0] = '\0';
	result = joinStrAtTheEnd(result, "====== Scan result ======\n");
	result = joinStrAtTheEnd(result, "Processed files: "); 
	result = joinStrAtTheEnd(result, countFiles);
	result = joinStrAtTheEnd(result, "\nJS detects: "); 
	result = joinStrAtTheEnd(result, jsD);
	result = joinStrAtTheEnd(result, "\nUNIX detects: "); 
	result = joinStrAtTheEnd(result, unD);
	result = joinStrAtTheEnd(result, "\nmacOS detects: "); 
	result = joinStrAtTheEnd(result, macD);
	result = joinStrAtTheEnd(result, "\nErrors: "); 
	result = joinStrAtTheEnd(result, err);
	result = joinStrAtTheEnd(result, "\nExection time: "); 
	result = joinStrAtTheEnd(result, hours); 
	result = joinStrAtTheEnd(result, ":"); 
	result = joinStrAtTheEnd(result, minuts);
	result = joinStrAtTheEnd(result, ":"); 
	result = joinStrAtTheEnd(result, secnd);
	result = joinStrAtTheEnd(result, "\n=========================");

	free(countFiles);
	free(jsD);
	free(unD);
	free(macD);

	free(err);
	free(hours);
	free(minuts);
	free(secnd);
	return result;
}

char *scaner(char *path)
{
	Info scanInfo;
	time_t timeStart;
	int timeRes;

	if (setDefaultScanInfo(&scanInfo) != 0)
		return (strdup("Error0 mutex init\n"));
	if (chdir(path) == -1)
	{
		pthread_mutex_destroy(&scanInfo.block);
		return (strdup("Error1 chdir to the path: No such file or directory\n"));
	}
	write(1, "== Scan service is started ==\n", 30);
	timeStart = time(NULL);
	if (searchingInCurrentDir(&scanInfo) == 1)
	{
		pthread_mutex_destroy(&scanInfo.block);
		return (strdup("Error2 searchingInCurrentDir getcwd / closedir\n"));
	}
	pthread_mutex_destroy(&scanInfo.block);
	timeRes =  time(NULL) - timeStart;
	// (void) timeRes;
	// char * result = NULL;
	char * result = makeScanReportLine(scanInfo, timeRes);
	return (result);
}
