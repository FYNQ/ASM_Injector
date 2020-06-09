#include <stdio.h>
#include <unistd.h>

struct fs_callbacks {
    int (*open_file)();
    int (*close_file)();
    int (*read_bytes)();
    int (*write_bytes)();
    struct fs_callbacks *next;
} FileSystems [10];


int write_ext2 () {
    fprintf(stderr, "\nCALLED EXT2\n");
}



struct info{
    int a;
    int b;
    char *c;
};

struct info g_info;

enum STATE{working, idle};


inline int 
add1(char a, unsigned int b){
    fprintf(stderr, "\nadd1\n");
    return a + b;
}

int state(enum STATE a, char *k) {
    fprintf(stderr, "\ncalled state\n");
}

int add2(float a, int b){
    fprintf(stderr, "\ncalled add2\n");
    int c = a + b;
    return c;
}

void fun_char(char *a) {
    fprintf(stderr, "Passed: %s", a);
    return;
}

int fun_void(void *a){
    fprintf(stderr, "\ncalled fun_void\n");
    return 0;
}


int blub2 (int a){
    return 0;
}


int blub(struct info *ptr_to_struct, int b){
    fprintf(stderr, "\nblub\n");
    int c = ptr_to_struct->a + b;
    return c;
}





#include<pthread.h>
pthread_t tid[2];

void* doSomeThing(void *arg)
{
    char fun[] = "test me";
    fprintf(stderr, "\n%s\n", fun);
    unsigned long i = 0;
    pthread_t id = pthread_self();

    if(pthread_equal(id,tid[0]))
    {
        fprintf(stderr, "\n First thread processing\n");
    }
    else
    {
        fprintf(stderr, "\n Second thread processing\n");
    }

    for(i=0; i<(0xFFFFFFFF);i++);

    return NULL;
}

int main(int argc, char **argv) {
    char fun[] = "main";
    struct info l_info;
    enum STATE s;
    fun_char(fun);
    s =  idle;
    blub2(4);
    //state(s, "ggg");
    struct fs_callbacks *f = &FileSystems [0];
    f->write_bytes = write_ext2;
    f->write_bytes();
    blub2(4);
    //dump_fun_info(fun, 4, 0);

    struct minfo{
        int a;
        int b;
        char *c;
    };
    static int blub_static = 5;
    struct minfo ldef;
    l_info.a = 5;
    //int c = blub(&ldef,4);
    ldef = (struct minfo) { .a = 1, .b = 0 }; 
    int x;
    int *z;
    int i = 20;
    x = 20;
    l_info.a = 20;
    l_info.b = 20;
    ldef.b = 20;
    int err;
    i = 0;
    while(i < 2)
    {
        err = pthread_create(&(tid[i]), NULL, &doSomeThing, NULL);
        if (err != 0)
            printf("\ncan't create thread :[%s]");
        else
            printf("\n Thread created successfully\n");

        i++;
    }
    sleep(5);
    return 0;
}

