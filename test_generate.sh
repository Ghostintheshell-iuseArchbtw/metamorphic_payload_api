#!/bin/bash

echo "Testing /generate endpoint 5 times..."
for i in {1..5}; do
    echo "Generate test $i:"
    curl -X POST http://localhost:8080/generate -H "x-api-key: your_api_key_here" > "generate_$i.txt"
    echo "MD5 hash:"
    md5sum "generate_$i.txt"
    echo "---"
done

echo -e "\nComparing generate outputs..."
for i in {1..5}; do
    for j in {1..5}; do
        if [ $i -ne $j ]; then
            echo "Comparing generate_$i.txt with generate_$j.txt:"
            diff "generate_$i.txt" "generate_$j.txt" || echo "Files are different"
            echo "---"
        fi
    done
done 