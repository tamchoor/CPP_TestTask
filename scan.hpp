#ifndef SCAN_H
# define SCAN_H

# include <iostream>
# include <ctime>
# include <libc.h>
# include <dirent.h>
# include <fstream>
# include <pthread.h>

# define UNIX_SRT		0
# define MAC_STR		1
# define JS_STR			2

# define THREAT_COUNT	3

# define UNIX_THREAT	"rm -rf ~/Documents"
# define MAC_THREAT		"system(\"launchctl load /Library/LaunchAgents/com.malware.agent\")"
# define JS_THREAT		"<script>evil_script()</script>"

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

/*scan_check*/
void	checkFileConsistsThreat(Info *scanInfo, char *filename);

/*utils*/
char	*ft_itoa(int n);
/*scan_utils*/
int		itIsJsFile(char *filename);
int		ft_strncmp_last(char *str1, char *str2, int len2);
char	*ft_strjoin_path(char const *s1, char const *s2);
int		setDefaultScanInfo(Info *scanInfo);
char	*joinStrAtTheEnd(char *dst, const char *src);
char	*makeScanReportLine(Info scanInfo, int timeRes);

#endif
