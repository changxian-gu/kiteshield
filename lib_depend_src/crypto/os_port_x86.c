#include "os_port_config.h"
int myosTolower(int c) {
    if (c >= 'A' && c <= 'Z')
        return c - 'A' + 'a';
    return c;
}

int myosToupper(int c) {
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 'A';
    return c;
}

int myosIsupper(int c) {
    return (c >= 'A' && c <= 'Z');
}

int myosIsdigit(int c) {
    return (c >= '0' && c <= '9');
}

int myosIsspace(int c) {
    return (c == ' ' || c == '\n' || c == '\t' || c == '\v' || c == '\f' || c == '\r');
}

void myosMemcpy(void *dest, const void *src, size_t n) {
    for (size_t i = 0; i < n; i++)
        ((char *) dest)[i] = ((char *) src)[i];
}

void* myosMemset(void *s, int c, size_t n) {
    unsigned char* p = s;
    while (n--)
        *p++ = (unsigned char) c;
    return s;
}

void myosMemmove(void *dest, void *src, size_t n) {
    for (size_t i = 0; i < n; i++)
        ((char *) dest)[i] = ((char *) src)[i];
}

int myosMemcmp(void* ptr1, void* ptr2, size_t num) {
    for (size_t i = 0; i < num; i++) {
        if ( ((unsigned char *)ptr1)[i] != ((unsigned char *)ptr2)[i] ) {
            return ((unsigned char *)ptr1)[i] - ((unsigned char *)ptr2)[i]; 
        }
    }
    return 0;
}

void* myosMemchr(const void* ptr, char c, size_t n) {
    char *pptr = (char *)ptr;
    for (int i = 0; i < n; i++) {
        if (pptr[i] == c)
            return pptr + i;
    }
    return NULL;
}

size_t myosStrlen(const char* s) {
    size_t cnt = 0;
    while (*s != '\0') {
        cnt++;
        s++;
    }
    return cnt;
}

int myosStrcmp(const char* str1, const char* str2) {
    while (*str1 && *str1 == *str2) {
        ++str1;
        ++str2;
    }
    return (int)(unsigned char)(*str1) - (int)(unsigned char)(*str2);
}

int myosStrncmp(const char* str1, const char* str2, size_t n) {
    while (*str1 && *str1 == *str2 && n) {
        ++str1;
        ++str2;
        n--;
    }
    return (int)(unsigned char)(*str1) - (int)(unsigned char)(*str2);
}

int myosStrcasecmp(const char* s1, const char* s2) {
    int offset, ch;
    unsigned char a, b;

    offset = 0;
    ch = 0;
    while(*(s1 + offset) != '\0') {
        if(*(s2 + offset) == '\0')
            return *(s1 + offset);
        a = (unsigned)*(s1 + offset);
        b = (unsigned)*(s2 + offset);
        ch = myosToupper(a) - myosToupper(b);
        if(ch != 0)
            return ch;
        offset++;
    }
    return ch;
}

int myosStrncasecmp(const char* s1, const char* s2, size_t n) {
    int offset, ch;
    unsigned char a, b;

    offset = 0;
    ch = 0;
    while(*(s1 + offset) != '\0' && n) {
        if(*(s2 + offset) == '\0')
            return *(s1 + offset);
        a = (unsigned)*(s1 + offset);
        b = (unsigned)*(s2 + offset);
        ch = myosToupper(a) - myosToupper(b);
        if(ch != 0)
            return ch;
        offset++;
        n--;
    }
    return ch;
}

char* myosStrchr(const char* str, char c) {
    char *p = str;
    while (*p != '\0') {
        if (*p == c)
            return p;
        ++p;
    }
    return NULL;
}

char* myosStrstr(const char* haystack, const char* needle) {
    if (needle == NULL || needle[0] == '\0')
        return haystack;
    // KMP
    // get next array
    int nlen = myosStrlen(needle);
    nlen = nlen > 65535 ? 65535 : nlen;
    int next[65536];
    myosMemset(next, 0, 65536);
    int j = 0;
    for (int i = 1; i < nlen; i++) {
        while (j > 0 && needle[i] != needle[j])
            j = next[j - 1];
        if (needle[i] == needle[j])
            j++;
        next[i] = j;
    }

    j = 0;
    int hlen = myosStrlen(haystack);
    for (int i = 0; i < hlen; i++) {
        while (j > 0 && haystack[i] != needle[j])
            j = next[j - 1];
        if (haystack[i] == needle[j])
            j++;
        if (j == nlen)
            return haystack + (i - nlen + 1);
    }
    return NULL;
}

char* myosStrcpy(char* dest, const char* src) {
    while (*src != '\0') {
        *dest = *src;
        ++dest;
        ++src;
    }
    return dest;
}

char* myosStrncpy(char* dest, const char* src, size_t n) {
    size_t i = 0;
    while (*src != '\0' && i < n) {
        *dest = *src;
        ++dest;
        ++src;
        ++i;
    }
    while (i < n)
        dest[i++] = '\0';
    return dest;
}

char* myosStrcat(char* s1, const char* s2) {
    if (s1 == NULL)
        return NULL;
    char *p = s1;
    while (*p != '\0')
        p++;
    while (*s2 != '\0')
        *p++ = *s2++;
    *p = '\0';
    return s1;
}