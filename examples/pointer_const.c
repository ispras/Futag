#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>

// malloc a number
int * new_number(){
	int * x = malloc(sizeof(int));
	return x;
}
// delete a number
void delete_number(int * x){
	free (x);
}
int main(void){
	int * N = new_number();
	delete_number(N);

	// init a number
	int x = 10;

	// declare a pointer to address of x
	int *a = &x;

	// declare a number b has value of a
	int b = *a;

	// declare a const number c has value of b
	const int c = b;

	// declare a const pointer to number d has address of b
	const int * d = &b;
	printf("d=%d\n", *d);
	return 0;
}
