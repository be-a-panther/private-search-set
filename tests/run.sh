#!/usr/bin/env bash
cd tests
echo "creating PSS"
cat ./word_list.txt | private-search-set --pss-home V1_1 --ingest --json-file templateV1_1.json
cat ./word_list.txt | private-search-set --pss-home V1_2 --ingest --json-file templateV1_2.json
cat ./word_list.txt | private-search-set --pss-home V2_0 --ingest --json-file templateV2_0.json
cat ./word_list.txt | private-search-set --pss-home V2_1 --ingest --json-file templateV2_1.json
cat ./word_list.txt | private-search-set --pss-home V2_2 --ingest --json-file templateV2_2.json
cat ./word_list.txt | private-search-set --pss-home V2_3 --ingest --json-file templateV2_3.json
cat ./word_list.txt | private-search-set --pss-home V2_4 --ingest --json-file templateV2_4.json
cat ./word_list.txt | private-search-set --pss-home V2_5 --ingest --json-file templateV2_5.json
cat ./word_list.txt | private-search-set --pss-home V2_6 --ingest --json-file templateV2_6.json

echo "checking PSS"
cat ./word_list.txt | private-search-set --pss-home V1_1 --check | wc -l 
cat ./word_list.txt | private-search-set --pss-home V1_2 --check | wc -l
cat ./word_list.txt | private-search-set --pss-home V2_0 --check | wc -l
cat ./word_list.txt | private-search-set --pss-home V2_1 --check | wc -l
cat ./word_list.txt | private-search-set --pss-home V2_2 --check | wc -l
cat ./word_list.txt | private-search-set --pss-home V2_3 --check | wc -l
cat ./word_list.txt | private-search-set --pss-home V2_4 --check | wc -l
cat ./word_list.txt | private-search-set --pss-home V2_5 --check | wc -l
