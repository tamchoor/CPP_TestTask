#include "scan.hpp"

int searchingInCurrentDir(Info *scanInfo);

void	cycleThroughFiles(DIR *direct, struct dirent *diren, char *dir, Info *scanInfo)
{
	char *new_dir;

	while (diren != NULL)
	{
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
	char * result = makeScanReportLine(scanInfo, timeRes);
	return (result);
}
