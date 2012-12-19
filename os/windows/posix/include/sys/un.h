#ifndef SYS_UN_H
#define SYS_UN_H

typedef int sa_family_t;
typedef int in_port_t;

 struct sockaddr_un
 {
	sa_family_t	sun_family; /* Address family */
	char		sun_path[]; /* Socket pathname */
};

#endif /* SYS_UN_H */
