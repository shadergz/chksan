#include <stdio.h>
#include <assert.h>
#include <getopt.h>
#include <malloc.h>
#include <string.h>

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/stat.h>

static int verbose = 0;

int main(int argc, char **argv)
{
    if (argc < 2)
        return puts("Invalid arguments number!");
    assert(argv[1]);

    int c;
    const char *short_ = ":dv";
    static const struct option long_[] = {
        {"device", required_argument, NULL, 'd'},
        {"verbose", no_argument, NULL, 'v'},
        {}
    };

    char *device = NULL;

    while((c = getopt_long_only(argc, argv, short_, long_, NULL)) != -1)
        switch(c) {
        case 'd':
            device = optarg;
            break;
        case 'v':
            verbose = 1;
		default: break;
		}
    if (!device) {
		if (optind)
			device = argv[optind];
		else
			return puts("Any device found!");
	}
	printf("Checking the device %s\n", device);

    puts("Checking if the device is mounted");

    int fd;
    char *table = NULL;

    puts("Opening the mount table");
    char *mount_table = "/etc/mtab";
    fd = open(mount_table, O_RDONLY);
    if (fd == -1)
        return printf("Can't open the mount table");

    puts("Allocating memory for the table content");
    if ((table = calloc(sizeof(char), 12300)))
        printf("12300 bytes allocated for the table at %p\n", table);
    else 
        return puts("Can't allocate 12300 bytes");
    
    if (read(fd, table, 12300) != -1)
        puts("Table content was read");

    puts("Closing the mount table");
    close(fd);

    char *dev_mount = NULL;

    char *table_zone = table;

    struct stat st;
    if (lstat(device, &st) == 0)
        printf("The device %s exist\n", device);
    else
        return printf("The device %s not exist\n", device);

	char *bak;
	for (char *te = strtok_r(table, " \n", &bak); te != NULL; te = strtok_r(NULL, " \n", &bak)) {
		if (strcmp(te, device) == 0) {
			if ((te = strtok_r(NULL, " \n", &bak))) {
				if ((dev_mount = strdup(te)))
					break;
			}
		}
	}

	if (dev_mount == NULL) {
		return printf("Mount point of %s not found\n", device);
	}
	else {
		printf("Mounted at %s\n", dev_mount);
	}

    puts("Checking for suspicious files in the device");

    static const char *sus_files[] = {
        "autorun",
        "autorun.inf",
        NULL
    };

    static const char *sus_ext_str[] = {
        "exe", "bat", "inf", "elf", ".ico", NULL
    };

    DIR *disk_dir = opendir(dev_mount);
    if (disk_dir == NULL)
        return printf("Can't open the directory at %s\n", dev_mount);

    int scanned = 0, detected = 0;
    int autorun = 0;
    int x_count = 0;

    int dangerous = 0;

    for (struct dirent *de = readdir(disk_dir); de; de = readdir(disk_dir))
    {
        char *l_bak;
        char *ls_file = de->d_name;
        scanned++;

        if (strlen(ls_file) <= 2 && *ls_file == '.')
            continue;
        else
            ls_file = strdup(ls_file);
 
        if (verbose)
            printf("Checking the file %s/%s\n", dev_mount, ls_file);

        const char *s_file = strtok_r(ls_file, ".", &l_bak);
        const char *ext = strtok_r(NULL, ".", &l_bak);

		(void)ext;

        for (const char **sus = sus_files; *sus; sus++)
        {
            if (strcmp(*sus, s_file) == 0) {
                detected++;
                if (strstr(*sus, "autorun") != NULL) {
                    char run_file[300];
                    char *auto_run_data = (char*)calloc(sizeof(char), 1000);
                    snprintf(run_file, sizeof(run_file), "%s/%s", dev_mount, de->d_name);
                    FILE *f = fopen(run_file, "r");
                    if (!f)
                        return printf("Can't open the file %s to read\n", run_file);
                    if (fread(auto_run_data, sizeof(char), 1000, f) != EOF) {
                        printf("Autorun data:\n%s", auto_run_data);
                        char *foo;
                        char *header = strtok_r(auto_run_data, "\n", &foo);

                        if (header)
                            if ((strcmp(header, "[autorun]")) == 0) {
                                autorun = 1;
                                x_count++;
                            }
                    }
                    free(auto_run_data);
                    fclose(f);
                }

                printf("The file %s in %s is potencially dangerous for your device check with clamAV\n", de->d_name, dev_mount);
                dangerous = 1;
            }

        }

        if (dangerous) {
            dangerous--;
            continue;
        }

        for (const char **sus_ext = sus_ext_str; *sus_ext; sus_ext++)
        {
            if (strcmp(*sus_ext, s_file) == 0) {
                detected++;
                if (strstr(*sus_ext, "exe") != NULL)
                    x_count++;
                printf("The file %s in %s is potencially dangerous for your device check with clamAV\n", s_file, dev_mount);
            }
        }

        free((char*)s_file);
    }

    printf("Scan summary:\t(%s)\nScanned files: %d\nDetections count: %d\nAutorun is present: %s\nExecutable count: %d\n",
		   dev_mount, scanned, detected, autorun ? "Yes" : "No", x_count);

    closedir(disk_dir);
    puts("Deallocating all objects");
    free(table_zone);
    free(dev_mount);

    return 0;
}

