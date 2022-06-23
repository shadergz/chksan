#include <stdio.h>
#include <assert.h>
#include <getopt.h>
#include <malloc.h>
#include <string.h>

#include <dirent.h>

#include <fcntl.h>
#include <unistd.h>

#include <sys/types.h>
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

    char *device = NULL;;

    while((c = getopt_long_only(argc, argv, short_, long_, NULL)) != -1)
        switch(c) {
        case 'd':
            device = optarg;
            break;
        case 'v':
            verbose = 1;
            break;
        }
    if (!device)
        if (optind)
            device = argv[optind];
        else
            return puts("Any device found!");
    printf("Checking the device %s\n", device);

    puts("Checking if the device is mounted");

    int fd;
    char *table = NULL;

    puts("Opening the mount table");
    char *mounttable = "/etc/mtab";
    fd = open(mounttable, O_RDONLY);
    if (fd == -1)
        return printf("Can't open the mount table");

    puts("Allocating memory for the table content");
    if ((table = calloc(sizeof(char), 12300)))
        printf("12300 bytes allocated for the table at %p\n", table);
    else 
        return puts("Can't allocate 12300 bytes");
    
    if (read(fd, table, 12300) != -1)
        puts("Table content readed");

    puts("Closing the mount table");
    close(fd);

    char *devmount = NULL;

    char *tablezone = table;

    struct stat st;
    if (lstat(device, &st) == 0)
        printf("The device %s exist\n", device);
    else
        return printf("The device %s not exist\n", device);

    if (table) {
        char *bak;
        for (char *te = strtok_r(table, " \n", &bak); te != NULL; te = strtok_r(NULL, " \n", &bak))
        {
            if (strcmp(te, device) == 0) {
                if (te = strtok_r(NULL, " \n", &bak))
                    if((devmount = strdup(te)))
                        break;
            }
        }
    }

    if (!devmount)
        return printf("Mount point of %s not found\n", device);
    else
        printf("Mounted at %s\n", device, devmount);
    
    puts("Checking for suspicious files in the device");

    const char *susfiles[] = {
        "autorun",
        "autorun.inf",
        NULL
    };

    const char *susexts[] = {
        "exe", "bat", "inf", "elf", ".ico", NULL
    };

    DIR *diskdir = opendir(devmount);
    if (diskdir == NULL)
        return printf("Can't open the directory at %s\n", devmount);

    int scanned = 0, detected = 0;
    int autorun = 0;
    int xcount = 0;

    int dangerous = 0;

    for (struct dirent *de = readdir(diskdir); de; de = readdir(diskdir))
    {
        char *bak;
        char *sfile = de->d_name;
        scanned++;

        if (strlen(sfile) <= 2 && *sfile == '.')
            continue;
        else
            sfile = strdup(sfile);
 
        if (verbose)
            printf("Checking the file %s/%s\n", devmount, sfile);

        const char *file = strtok_r(sfile, ".", &bak);
        const char *ext = strtok_r(NULL, ".", &bak);

        for (const char **sus = susfiles; *sus; sus++)
        {
            if (strcmp(*sus, sfile) == 0) {
                detected++;
                if (strstr(*sus, "autorun") != NULL) {
                    char runfile[100];
                    char *autorundata = calloc(sizeof(char), 1000);
                    snprintf(runfile, sizeof(runfile), "%s/%s", devmount, de->d_name);
                    FILE *f = fopen(runfile, "r");
                    if (!f)
                        return printf("Can't open the file %s to read\n", runfile);
                    if (fread(autorundata, sizeof(char), 1000, f) != EOF) {
                        printf("Autorun data:\n%s", autorundata);
                        char *foo;
                        char *header = strtok_r(autorundata, "\n", &foo);

                        if (header)
                            if ((strcmp(header, "[autorun]")) == 0) {
                                autorun = 1;
                                xcount++;
                            }
                    }
                    free(autorundata);
                    fclose(f);
                }

                printf("The file %s in %s is potencially dangerous for your device check with clamAV\n", de->d_name, devmount);
                dangerous = 1;
            }

        }

        if (dangerous) {
            dangerous--;
            continue;
        }

        for (const char **susext = susexts; *susext; susext++) 
        {
            if (strcmp(*susext, sfile) == 0) {
                detected++;
                if (strstr(*susext, "exe") != NULL)
                    xcount++;
                printf("The file %s in %s is potencially dangerous for your device check with clamAV\n", sfile, devmount);
            }
        }

        free(sfile);
    }

    printf("Scan summary:\t(%s)\nScanned files: %d\nDetections count: %d\nAutorun is present: %s\nExecutable count: %d\n",
        devmount, scanned, detected, autorun ? "Yes" : "No", xcount);

    closedir(diskdir);
    puts("Deallocating all objects");
    free(tablezone);
    free(devmount);

    return 0;
}

