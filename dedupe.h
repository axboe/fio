#ifndef DEDUPE_H
#define DEDUPE_H

/*
 * Defines the ratio of seeds we maintain in memory opposed to seeds we calculate in runtime
 * E.g. a ratio of 1k means we maintain 1 seed per 1k pages we expect in the dedupe_workset
 */
#define LOW_MEMORY_DEDUPE_WORKSET_RATIO 1024

int init_dedupe_working_set_seeds(struct thread_data *td);

#endif
