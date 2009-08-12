/**
 * Linked list implementation in C.
 * Originally from Wikipedia.
 */

#include <stdio.h>
#include <stdlib.h>

struct list_data {
    int data;
};

typedef struct list_data list_data;

struct list_node {
    int data;
    list_data ld;
    struct list_node *next;
};

typedef struct list_node node;

node *list_add_data(node **p, int i)
{
    node *n = malloc(sizeof(node));

    if (n == NULL) {
	return NULL;
    }

    n->next = *p; // the previous element (*p) now becomes the "next" element
    *p = n;       // add new empty element to the front (head) of the list
    n->data = i;

    return *p;
}

node *list_add(node **p, list_data ld)
{
    node *n = malloc(sizeof(node));

    if (n == NULL) {
	return NULL;
    }

    n->next = *p;
    *p = n;
    n->ld = ld;

    return *p;
}

void list_remove(node **p)
{
    if (*p != NULL) {
	node *n = *p;
	*p = (*p)->next;
	free(n);
    }
}

node **list_search(node **n, int i)
{
    while (*n != NULL) {
	if ((*n)->data == i) {
	    return n;
	}
	n = &(*n)->next;
    }
    return NULL;
}

void list_print(node *n)
{
    if (n == NULL) {
	printf("List is empty.\n");
	return;
    }
    int i = 0;
    while (n != NULL) {
	printf("node %d: n = %p, n->next = %p, n->data = %d, n->ld.data = %d\n", i, n, n->next, n->data, n->ld.data);
	n = n->next;
	i++;
    }
}

int main(void)
{
    node *n = NULL;

    list_add_data(&n, 0); // list: 0
    list_add_data(&n, 1); // list: 1 0
    list_add_data(&n, 2); // list: 2 1 0
    list_add_data(&n, 3); // list: 3 2 1 0
    list_add_data(&n, 4); // list: 4 3 2 1 0
    list_print(n);

    printf("\n");

    list_remove(&n);                 // remove first (4)
    list_remove(&n->next);           // remove new second (2)
    list_remove(list_search(&n, 1)); // remove cell containing 1 (first)
    list_remove(&n->next);           // remove second to last node (0)
    list_remove(&n);                 // remove last (3)
    list_print(n);

    printf("\n");

    list_data ld;
    ld.data = 22;

    list_add_data(&n, 44);
    list_add(&n, ld);

    list_print(n);

    return 0;
}
