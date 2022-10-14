#include "scan.hpp"

void	*checkOneLineConsistThreat(void	*checkingCurrent)
{
	checkingData	*checking = (checkingData *) checkingCurrent;
	std::string fileLine = *checking->fileLine;
	std::string searchLine = *checking->searchLine;

	size_t i = 0;
	i = fileLine.find(searchLine, i);
	if (i != std::string::npos)
	{
		pthread_mutex_lock(&checking->scanInfo->block);
		++checking->scanInfo->detect[checking->indx];
		pthread_mutex_unlock(&checking->scanInfo->block);
	}
	return ((void *)i);
}

checkingData	*allocMemForChecking(int itIsJs, Info *scanInfo)
{
	checkingData	*checking;
	checkingData	*firstChecking;

	checking = (checkingData *)calloc(1, sizeof(checkingData));
	if (!checking)
		return NULL;
	checking->scanInfo = scanInfo;
	firstChecking = checking;
	int i = 1;
	while (i < THREAT_COUNT - 1) // -1 тк JS отдельно
	{
		checking->next = (checkingData *)calloc(1, sizeof(checkingData));
		if (!checking->next)
		{
			while(firstChecking)
			{
				checking = firstChecking->next;
				free(firstChecking);
				firstChecking = checking;
			}
			return NULL;
		}
		++i;
		checking->next->scanInfo = scanInfo;
		checking = checking->next;
		checking->next = NULL;
	}
	if (itIsJs == 0)
	{
		checking->next = (checkingData *)calloc(1, sizeof(checkingData));
		if (!checking->next)
		{
			while(firstChecking)
			{
				checking = firstChecking->next;
				free(firstChecking);
				firstChecking = checking;
			}
			return NULL;
		}
		checking->next->scanInfo = scanInfo;
		checking->next->next = NULL;
	}
	return firstChecking;
}

/*Чтение построчно из файла и запуск на каждую сроку отдельных 
потоков с проверкой на наличие “подозрительного” содержимого 
(можно было сделать потоки на чтение каждого файла и проверять содержимое циклом, 
так как по заданию подозрительных строк всего 3.
Но я подумала, что обычно критериев вредоносности больше, чем файлов в папке 
заданной клиентом - поэтому потоки на каждый критерий. Если бы пришлось увеличивать 
количество "подозрительных" срок - их можно не вписывать через хэдер, а парсить сюда в search из файла.
 Изменив при этом количесво скрок THREAT_COUNT в хэдер файле )
*/
void	checkFileConsistsThreat(Info *scanInfo, char *filename)
{
	int itIsJs = itIsJsFile(filename); // 0 - js
	std::fstream file(filename);
	checkingData	*checking;
	checkingData	*firstChecking;

	if (file)
	{
		++scanInfo->countFiles;
		int threatCount = THREAT_COUNT;
		std::string search[THREAT_COUNT] = {UNIX_THREAT, MAC_THREAT, JS_THREAT}; 
		std::string fileLine;

		checking = allocMemForChecking(itIsJs, scanInfo);
		if (!checking)
		{
			write(2, "Error malloc\n", 13);
			goto mallocerror;
		}
		firstChecking = checking;
		int ix = 0;
		while ((itIsJs == 0 && ix < threatCount) || (itIsJs != 0 && ix < threatCount - 1))
		{
			checking->searchLine = &search[ix];
			checking = checking->next;
			++ix;
		}

		while (getline(file, fileLine))
        {
			int indx = 0;
			checking = firstChecking;
			while ((itIsJs == 0 && indx < threatCount) || (itIsJs != 0 && indx < threatCount - 1))
			{
				checking->fileLine = &fileLine;
				checking->indx = indx;
				if (pthread_create(&checking->thread, NULL, checkOneLineConsistThreat, (checking)) != 0)
				{
					while(firstChecking)
					{
						checking = firstChecking->next;
						free(firstChecking);
						firstChecking = checking;
					}
					write(2, "Error pthread_create\n", 21);
					goto mallocerror;
				}
				++indx;
				if ((itIsJs == 0 && indx < threatCount) || (itIsJs != 0 && indx < threatCount - 1))
				{
					if (checking->next)
						checking = checking->next;
					else
						checking = firstChecking;
				}
			}
			checking = firstChecking;
			while(checking)
			{
				pthread_join (checking->thread, NULL);
				checking = checking->next;
			}

		}
		while(firstChecking)
		{
			checking = firstChecking->next;
			free(firstChecking);
			firstChecking = checking;
		}
	}
	else
	{
		mallocerror:
			++scanInfo->errors;
	}
}
