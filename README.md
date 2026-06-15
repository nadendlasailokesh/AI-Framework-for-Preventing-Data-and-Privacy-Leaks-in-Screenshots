# PII Guard: AI Framework for Preventing Data and Privacy Leaks in Screenshots

## Overview

PII Guard is an AI-powered privacy protection framework designed to prevent accidental exposure of sensitive information in screenshots before they are shared. The system combines Computer Vision, OCR, NLP, and Explainable AI to identify and protect Personally Identifiable Information (PII) in real time.

## Features

* Detection of textual and visual PII
* YOLOv8-based object detection
* OCR-based text extraction
* Transformer-based Named Entity Recognition (NER)
* Hybrid risk assessment and explainable alerts
* Automatic irreversible redaction
* Real-time privacy protection

## Technologies Used

* Python
* YOLOv8
* PaddleOCR / EasyOCR
* Transformers (BERT/DistilBERT)
* OpenCV
* NumPy
* Flask / FastAPI

## Datasets

* MIDV-2019
* SROIE
* FUNSD
* AI4Privacy
* Custom screenshot dataset

## Workflow

1. Input Screenshot
2. Visual PII Detection using YOLOv8
3. Text Extraction using OCR
4. Spatial Text Reconstruction
5. Contextual PII Validation using NLP
6. Risk Assessment
7. Automatic Redaction
8. Secure Output Generation

## Results

* F1-Score: 90%
* Precision: 92%
* Recall: 88%
* Real-time Processing: ~8 FPS

## Applications

* Privacy-preserving screenshot sharing
* Enterprise data protection
* Financial document security
* Identity document protection
* Social media privacy

## Future Work

* Multilingual PII detection
* Mobile deployment
* Metadata-aware reasoning
* Expanded international document support



