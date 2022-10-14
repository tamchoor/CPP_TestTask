#ifndef SCANNER_HPP
# define SCANNER_HPP

#include "scan.hpp"

class Scanner
{
	public:
		Scanner(){
			scanerRes = NULL;
		};

		~Scanner(){
			if (scanerRes)
				free(scanerRes);
		};

		char * startScanInDir(char *path)
		{
			scanerRes = scaner(path);
			return (scanerRes);
		}

	private:
		char *scanerRes;

};

#endif
