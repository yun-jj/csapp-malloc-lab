/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "ateam",
    /* First member's full name */
    "Harry Bovik",
    /* First member's email address */
    "bovik@cs.cmu.edu",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""
};

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)


#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

/*
* some macro
*/
#define WSIZE 4
#define DSIZE 8
#define OVER_HEAD 8
#define INIT_MM_TABLE_ENTRY_NUMBER 8
#define INIT_MM_TABLE_SIZE (INIT_MM_TABLE_ENTRY_NUMBER * (WSIZE))
#define FIRST_CHUNK_SIZE 2048 

#define PACK(size, alloc) ((size) | (alloc)) 
#define GET(p) (*(u_int32_t*)(p))
#define PUT(p, val) (*(u_int32_t*)(p) = (val))
#define GET_SIZE(p) (GET(p) & (~0x7))
#define GET_ALLOC(p) (GET(p) & (0x1)) //the least bit is alloc tag
#define HDRP(bp) ((char*)(bp) - WSIZE - DSIZE) 
#define RTRP(bp) ((char*)(bp) + GET_SIZE(HDRP(bp)) - (DSIZE * 2))
#define GET_TABLE_ENTRY(table, i) (*((u_int32_t*)(table) + (i)))
/*
*  some var
*/
static void *mm_table;
static size_t mm_table_size;
static int mm_table_entry_number;

/*
* some function
*/
size_t get_table_entry_index(size_t size)
{
    size_t list_size = (1 << 4), table_index = 0;

    while (size > list_size) //find first-fit list
    {
        list_size = (list_size << 1);
        table_index++;
    }

    return table_index;
}

void insert_chunk(void *bp)
{
    int entry_index = get_table_entry_index(GET_SIZE(HDRP(bp)));
    if (entry_index >= mm_table_entry_number) realloc_mm_table();
    u_int32_t *pre_next_ptr = &GET_TABLE_ENTRY(mm_table, entry_index);
    u_int32_t *cur_n_next_ptr = GET_TABLE_ENTRY(mm_table, entry_index);

    while (cur_n_next_ptr != NULL 
    && GET_SIZE(HDRP(bp)) < GET_SIZE(HDRP((cur_n_next_ptr + 1))))
    {
        pre_next_ptr = cur_n_next_ptr;
        cur_n_next_ptr = *cur_n_next_ptr;
    }

    PUT(pre_next_ptr, (bp - WSIZE));
    PUT((bp - WSIZE), cur_n_next_ptr);
    if (&GET_TABLE_ENTRY(mm_table, entry_index) == pre_next_ptr) // insert list head
        PUT((bp - DSIZE), 0x0);
    else PUT((bp - DSIZE), (pre_next_ptr - 1));
    if (cur_n_next_ptr != NULL)
        PUT((cur_n_next_ptr - 1), (bp - DSIZE));
}
/*
* remove_chunk in list 
*/
void remove_chunk(void *bp)
{
    u_int32_t *pre_preptr = GET((bp - DSIZE));
    u_int32_t *next_nextptr = GET((bp - WSIZE));

    if (pre_preptr == NULL)
    {
        GET_TABLE_ENTRY(mm_table, get_table_entry_index(GET_SIZE(HDRP(bp)))) = next_nextptr;
        if (next_nextptr != NULL) PUT((next_nextptr - 1), 0x0);
    }
    else if (pre_preptr != NULL)
    {
        PUT((pre_preptr + 1), next_nextptr);
        if (next_nextptr != NULL)
            PUT((next_nextptr - 1), pre_preptr);
    }
}
/*
* return after split chunk bp ptr
* pass size is contain all chunk part even the meta data
* split_chunk only set the chunk size meta data 
* return remaining chunk bp ptr
*/
void* split_chunk(void *bp, size_t newsize)
{
    void *remaining_chunk_bp = (bp + newsize);
    size_t remaining_chunk_size = GET_SIZE(HDRP(bp)) - newsize;

    // set new chunk
    PUT(HDRP(bp), newsize);
    PUT(RTRP(bp), newsize);
    // set remaining chunk
    PUT(HDRP(remaining_chunk_bp), remaining_chunk_size);
    PUT(RTRP(remaining_chunk_bp), remaining_chunk_size);

    return remaining_chunk_bp;
}

// return fit chunk bp ptr
void* find_chunk(u_int32_t *cur_node, size_t request_size)
{
    while (cur_node != NULL)
    {
        size_t cur_node_size = GET_SIZE((cur_node - 2));
        if (cur_node_size - (2 * DSIZE) >= request_size) 
            return (void*)(cur_node + 1);
        cur_node = *cur_node;
    }

    return (void*)-1;
}

void realloc_mm_table(void)
{
    int new_entry_number = 2 * mm_table_entry_number;
    size_t new_table_size = DSIZE * new_entry_number;

    void *new_mm_table = mem_sbrk(new_table_size);
    if (new_mm_table == (void*)-1) return new_mm_table;
    memset(new_mm_table, 0x0, new_table_size);
    memcpy(new_mm_table, mm_table, mm_table_size);

    void *bp = mm_table + DSIZE + WSIZE;
    PUT(HDRP(bp), PACK(mm_table_size, 0x0));
    PUT(RTRP(bp), PACK(mm_table_size, 0x0));

    void *return_table = mm_table;
    mm_table = new_mm_table;
    mm_table_size = new_table_size;
    mm_table_entry_number = new_entry_number;
    insert_chunk(bp);
}

/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    void *table = mem_sbrk(INIT_MM_TABLE_SIZE); 
    if (table == (void*)-1) return -1;
    memset(table, 0, INIT_MM_TABLE_SIZE);

    void *first_chunk = mem_sbrk(FIRST_CHUNK_SIZE);
    if (first_chunk == (void*)-1) return -1;
    //set first chunk meta data
    u_int32_t meta_data = PACK(FIRST_CHUNK_SIZE, 0x0);
    PUT(first_chunk, meta_data);
    PUT((first_chunk + INIT_MM_TABLE_SIZE - WSIZE), meta_data);

    mm_table = table;
    mm_table_entry_number = INIT_MM_TABLE_ENTRY_NUMBER;
    mm_table_size = INIT_MM_TABLE_SIZE;
    insert_chunk(first_chunk + DSIZE + WSIZE);
    
    return 1;
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
    // int newsize = ALIGN(size + SIZE_T_SIZE);
    // void *p = mem_sbrk(newsize);
    // if (p == (void *)-1)
	// return NULL;
    // else {
    //     *(size_t *)p = size;
    //     return (void *)((char *)p + SIZE_T_SIZE);
    // }
    size_t newsize = ALIGN(size + SIZE_T_SIZE);
    size_t entry_index = get_table_entry_index(newsize + (2 * DSIZE));
    size_t tmp_entry_index = entry_index;
    u_int32_t *cur_node;

    for (; mm_table_entry_number > tmp_entry_index; tmp_entry_index++)
    {
        cur_node = GET_TABLE_ENTRY(mm_table, tmp_entry_index);
        void *bp = find_chunk(cur_node, newsize);
        if (bp != (void*)-1) // find fit chunk
        {
            // remove return chunk in list
            remove_chunk(bp);
            size_t chunk_size = GET_SIZE(HDRP(bp));
            if (((int)chunk_size) - (((int)newsize) + 32) > 0) //split_chunk
            {
                void *remaining_chunk_bp = split_chunk(bp, newsize + (2 * DSIZE));
                // set remaining chunk and insert list
                u_int32_t new_meta_data = PACK(GET_SIZE(HDRP(remaining_chunk_bp)), 0x0);
                PUT(HDRP(remaining_chunk_bp), new_meta_data);
                PUT(RTRP(remaining_chunk_bp), new_meta_data);
                insert_chunk(remaining_chunk_bp); // insert remaining chunk
            }
            // set return meta data
            u_int32_t new_meta_data = PACK(GET_SIZE(HDRP(bp)), 0x1);
            PUT(HDRP(bp), new_meta_data);
            PUT(RTRP(bp), new_meta_data);
            return (bp - WSIZE);
        }
    }

    if (entry_index >= mm_table_entry_number) // request size out of table size range
        realloc_mm_table();

    size_t alloc_size = newsize + (2 * DSIZE);
    void *return_chunk = mem_sbrk(alloc_size); 
    if (return_chunk == (void*)-1)
        return return_chunk;
    void *additional_chunk = mem_sbrk(alloc_size);
    if (additional_chunk == (void*)-1)
        return additional_chunk;
    // set meta data
    u_int32_t new_meta_data = PACK(alloc_size, 0x1);
    PUT(return_chunk, new_meta_data);
    PUT((return_chunk + alloc_size - WSIZE), new_meta_data);
 
    new_meta_data = PACK(new_meta_data, 0x0);
    PUT(additional_chunk, new_meta_data);
    PUT((additional_chunk + alloc_size - WSIZE), new_meta_data);    
    insert_chunk((additional_chunk + WSIZE + DSIZE));
    return (return_chunk + DSIZE);
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
    if (ptr == NULL) return;

    void *bp = ptr + WSIZE;
    size_t size = GET_SIZE(HDRP(bp));
    PUT(HDRP(bp), PACK(size, 0x0));
    PUT(RTRP(bp), PACK(size, 0x0));

    void *chunk_start_byte = (bp - DSIZE - WSIZE);
    void *chunk_end_byte = (chunk_start_byte + size - 1);

    if (!(chunk_start_byte == mem_heap_lo() ||
    chunk_start_byte == (mm_table + mm_table_size) || GET_ALLOC((chunk_start_byte - WSIZE))))
    {
        size_t pre_chunk_size = GET_SIZE((chunk_start_byte - WSIZE));
        bp = (chunk_start_byte - pre_chunk_size + DSIZE + WSIZE);
        remove_chunk(bp);
        size = pre_chunk_size + size;
        u_int32_t new_meta_data = PACK(size, 0x0);
        PUT(HDRP(bp), new_meta_data);
        PUT(RTRP(bp), new_meta_data);
    }

    if (!(chunk_end_byte == mem_heap_hi() ||
    (chunk_end_byte + 1) == mm_table || GET_ALLOC((chunk_end_byte + 1))))
    {
        size_t next_chunk_size = GET_SIZE((chunk_end_byte + 1));
        remove_chunk(chunk_end_byte + 1 + DSIZE + WSIZE);
        size = next_chunk_size + size;
        u_int32_t new_meta_data = PACK(size, 0x0);
        PUT(HDRP(bp), new_meta_data);
        PUT(RTRP(bp), new_meta_data);
    }

    insert_chunk(bp);
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    // void *oldptr = ptr;
    // void *newptr;
    // size_t copySize;
    
    // newptr = mm_malloc(size);
    // if (newptr == NULL)
    //   return NULL;
    // copySize = *(size_t *)((char *)oldptr - SIZE_T_SIZE);
    // if (size < copySize)
    //   copySize = size;
    // memcpy(newptr, oldptr, copySize);
    // mm_free(oldptr);
    // return newptr;
    if (ptr == NULL) return mm_malloc(size);
    if (size == 0)
    {
        mm_free(ptr);
        return 0;
    }

    void *bp = ptr + WSIZE;
    size_t old_size = GET_SIZE(HDRP(bp));
    size_t new_size = ALIGN(size + SIZE_T_SIZE) + (2 * DSIZE);
    size_t copysize = old_size - 2 * DSIZE;

    if (new_size == old_size) return ptr; 
    else if (new_size < old_size)
    {
        if (((int)old_size) - ((int)new_size) - (2 * DSIZE) > 0)
        {
            void *remaining_chunk_bp = split_chunk(bp, new_size);
            insert_chunk(remaining_chunk_bp); 
            PUT(HDRP(bp),PACK(new_size, 0x1));
            PUT(RTRP(bp), PACK(new_size, 0x1));
        }
        return ptr; 
    }
    else if (new_size > old_size)
    {
        void *chunk_start_byte = bp - DSIZE - WSIZE;
        void *chunk_end_byte = chunk_start_byte + old_size - 1;

        if (!(chunk_start_byte == mem_heap_lo() ||
        chunk_start_byte == (mm_table + mm_table_size) || GET_ALLOC((chunk_start_byte - WSIZE))))
        {
            size_t pre_chunk_size = GET_SIZE((chunk_start_byte - WSIZE));
            void *pre_chunk_bp = chunk_start_byte - pre_chunk_size + DSIZE + WSIZE;
            remove_chunk(pre_chunk_bp);
            old_size = pre_chunk_size + old_size;
            PUT(HDRP(pre_chunk_bp), PACK(old_size, 0x1));
            PUT(RTRP(pre_chunk_bp), PACK(old_size, 0x1));
            bp = pre_chunk_bp;
        }

        if (!(chunk_end_byte == mem_heap_hi() ||
        (chunk_end_byte + 1) == mm_table || GET_ALLOC((chunk_end_byte + 1))))
        {
            size_t next_chunk_size = GET_SIZE((chunk_end_byte + 1));
            void *next_chunk_bp = chunk_end_byte + 1 + DSIZE + WSIZE;
            remove_chunk(next_chunk_bp);
            old_size = next_chunk_size + old_size;
            PUT(HDRP(bp), PACK(old_size, 0x1));
            PUT(RTRP(bp), PACK(old_size, 0x1));
        }


        if (old_size >= new_size)
        {
            if (((int)old_size) - ((int)new_size) - (2 * DSIZE) > 0)
            {
                memmove((bp - WSIZE), ptr, copysize);
                void *remaining_chunk = split_chunk(bp, new_size);
                insert_chunk(remaining_chunk);
                PUT(HDRP(bp),PACK(new_size, 0x1));
                PUT(RTRP(bp), PACK(new_size, 0x1));
                return (bp - WSIZE);
            }
            memmove((bp - WSIZE), ptr, copysize);
            return (bp - WSIZE);
        }
        else if (old_size < new_size)
        {
            void *fit_chunk_bp = 0;
            int entry_index = get_table_entry_index(new_size);
            for (; mm_table_entry_number > entry_index; entry_index++)
            {
                u_int32_t *cur_chunk_next_ptr = GET_TABLE_ENTRY(mm_table, entry_index);
                fit_chunk_bp = find_chunk(cur_chunk_next_ptr, new_size);
                if (fit_chunk_bp != (void*)-1)
                {
                    remove_chunk(fit_chunk_bp);
                    size_t fit_chunk_size = GET_SIZE(HDRP(fit_chunk_bp));
                    memmove((fit_chunk_bp - WSIZE), ptr, copysize);
                    PUT(HDRP(fit_chunk_bp),PACK(fit_chunk_size, 0x1));
                    PUT(RTRP(fit_chunk_bp), PACK(fit_chunk_size, 0x1));
                    mm_free(ptr);
                    return (fit_chunk_bp - WSIZE);
                }
            }
            void *new_chunk_start_byte = mem_sbrk(new_size);  
            fit_chunk_bp = new_chunk_start_byte + WSIZE + DSIZE;
            memmove((fit_chunk_bp - WSIZE), ptr, copysize);
            PUT(HDRP(fit_chunk_bp), PACK(new_size, 0x1));
            PUT(RTRP(fit_chunk_bp), PACK(new_size, 0x1));
            mm_free(ptr);
            return (fit_chunk_bp - WSIZE);
        }
    }
}

int mm_check()
{
    size_t mem_size = mem_heapsize();
    size_t in_list_size = 0;

    for (int i = 0; mm_table_entry_number > i; i++)
    {
        u_int32_t *cur_chunk_next_ptr = GET_TABLE_ENTRY(mm_table, i);
        while (cur_chunk_next_ptr != NULL)
        {
            in_list_size += GET_SIZE((cur_chunk_next_ptr - 2));
            cur_chunk_next_ptr = *cur_chunk_next_ptr;
        }
    }
    printf("mem_size: %u, in_list_size: %u\n", mem_size, in_list_size);
}
