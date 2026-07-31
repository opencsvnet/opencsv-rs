#ifndef OPENCESV_BENCH_H
#define OPENCESV_BENCH_H

/* Runs the full OpenCSV prover benchmark (mint, two transfer hops, redeem).
 * Returns a newly allocated JSON string with prove/verify times and proof
 * sizes. Call from a background thread — this takes seconds to minutes.
 * Free the result with opencsv_bench_free_string(). */
char *opencsv_bench_run(void);

/* Frees a string returned by opencsv_bench_run(). */
void opencsv_bench_free_string(char *s);

#endif /* OPENCESV_BENCH_H */
