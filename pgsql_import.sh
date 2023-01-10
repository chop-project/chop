#!/bin/bash

USERNAME=ubuntu
DBNAME=exceptionalresearch

psql -U ${USERNAME} ${DBNAME} < dbexport.pgsql
