#include "scan.hpp"

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
