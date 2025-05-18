#!/bin/bash

echo "Testing /generate endpoint 5 times..."
for i in {1..5}; do
    echo "Generate test $i:"
    curl -X POST http://localhost:8080/generate -H "x-api-key: your_api_key_here" > "generate_$i.txt"
    md5sum "generate_$i.txt"
done

echo -e "\nTesting /download endpoint 5 times..."
for i in {1..5}; do
    echo "Download test $i:"
    curl -X GET http://localhost:8080/download/payload.ps1 -H "x-api-key: your_api_key_here" -o "download_$i.ps1"
    md5sum "download_$i.ps1"
done

echo -e "\nComparing generate outputs..."
for i in {1..5}; do
    for j in {1..5}; do
        if [ $i -ne $j ]; then
            echo "Comparing generate_$i.txt with generate_$j.txt:"
            diff "generate_$i.txt" "generate_$j.txt" || echo "Files are different"
        fi
    done
done

echo -e "\nComparing download outputs..."
for i in {1..5}; do
    for j in {1..5}; do
        if [ $i -ne $j ]; then
            echo "Comparing download_$i.ps1 with download_$j.ps1:"
            diff "download_$i.ps1" "download_$j.ps1" || echo "Files are different"
        fi
    done
done

echo -e "\nComparing generate vs download..."
for i in {1..5}; do
    echo "Comparing generate_$i.txt with download_$i.ps1:"
    diff "generate_$i.txt" "download_$i.ps1" || echo "Files are different"
done 