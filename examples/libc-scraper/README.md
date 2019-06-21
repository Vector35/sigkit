# libc-scraper

This directory includes scripts that demonstrate how sigkit can scaled up performantly.

The goal of libc-scraper is to scrape *.debs for Ubuntu libcs, process them using headless mode, and generate space-efficient signature libraries.

batch_process.py demonstrates how to generate signatures using headless mode.

Of special interest is merge_ubuntu.py, which shows how you can make create small signature libraries that combine multiple versions of the same library.
Using clever tricks, it is possible to aggressively deduplicate across multiple versions while maintaining accuracy.
