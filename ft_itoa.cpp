#include <libc.h>

static int	len_of_nbr(long nbr)
{
	int nbrLen = 0;

	if (nbr < 0)
	{
		nbrLen++;
		nbr = nbr * (-1);
	}
	while (nbr > 0)
	{
		nbr = nbr / 10;
		nbrLen++;
	}
	return (nbrLen);
}

static char	*convert_to_char(long nbr)
{
	char	*strNbr;
	int		nbrLen =  len_of_nbr(nbr);
	int minus = 0;

	strNbr = (char *) calloc((nbrLen + 1), sizeof(char));
	if (!strNbr)
		return (NULL);
	if (nbr < 0)
	{
		minus = -1;
		nbr = nbr * (-1);
	}
	strNbr[nbrLen] = '\0';
	nbrLen--;
	while (nbrLen > 0 || (minus != -1 && nbrLen >= 0))
	{
		strNbr[nbrLen] = (char)(nbr % 10) + '0';
		nbr = nbr / 10;
		nbrLen--;
	}
	if (minus == -1)
		strNbr[0] = '-';
	return (strNbr);
}

char	*ft_itoa(int n)
{
	char	*strNbr;
	long	nbr;

	nbr = (long) n;
	strNbr = 0;
	if (nbr == 0)
		return (strdup("0"));
	strNbr = convert_to_char(nbr);
	return (strNbr);
}
