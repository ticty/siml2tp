#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "../defines.h"


#define MAXSECRETLEN	256     /* max length of password or secret */
#define VERSION         "2.4.5" /* version */

/* may comment line below to ignore version check, but not recommend */
char pppd_version[] = VERSION;


enum opt_type {
	o_special_noarg = 0,
	o_special = 1,
	o_bool,
	o_int,
	o_uint32,
	o_string,
	o_wild
};

typedef struct {
	char	*name;
	enum opt_type type;
	void	*addr;
	char	*description;
	unsigned int flags;
	void	*addr2;
	int	upper_limit;
	int	lower_limit;
	const char *source;
	short int priority;
	short int winner;

} option_t;


static int passwdfd = -1;
static char save_passwd[MAXSECRETLEN];

static option_t options[] = {
    { "passwordfd", o_int, &passwdfd, "",   0, NULL, 0, 0, NULL, 0, 0 },
    { NULL,         0,     NULL,      NULL, 0, NULL, 0, 0, NULL, 0, 0 }
};


extern void add_options __P((option_t *));
extern int (*pap_check_hook) __P((void));
extern int (*pap_passwd_hook) __P((char *user, char *passwd));
extern int (*chap_check_hook) __P((void));
extern int (*chap_passwd_hook) __P((char *user, char *passwd));


static int pwfd_check (void)
{
    return 1;
}


static int pwfd_passwd ( char *user, char *passwd )
{
    int readgood, red;

    UNUSED_ARGUMENT(user);

    if (passwdfd == -1)
	{
		return -1;
	}

    if (passwd == NULL)
	{
		return 1;
	}

    if (passwdfd == -2)
    {
		strcpy (passwd, save_passwd);
		return 1;
    }

    readgood = 0;
    
    do
    {
		red = read( passwdfd, passwd + readgood, MAXSECRETLEN - 1 - readgood );
	
		if( red == 0) 
	    {
	    	break;
	    }
		else if (red < 0)
		{
	    	readgood = -1;
	    	break;
		}
	
		readgood += red;
    
    }while ( readgood < MAXSECRETLEN - 1 );

    close (passwdfd);

    if (readgood < 0)
	{
		return 0;
	}

    passwd[readgood] = 0;
    strcpy (save_passwd, passwd);
    passwdfd = -2;

    return 1;
}


void plugin_init (void)
{
    add_options (options);

    pap_check_hook = pwfd_check;
    pap_passwd_hook = pwfd_passwd;

    chap_check_hook = pwfd_check;
    chap_passwd_hook = pwfd_passwd;
}
