# Getting Started

Follow these steps to set up and run the project on your local machine.

**FIRSTLY UNPACK THE "compressed_data" file in the project folder.**

# Prerequisites

Python 3.8 or higher



pip (Python package installer)



# Steps

### **Step 1:** Install Required Libraries

Install all the necessary Python libraries using the requirements.txt file.



pip install -r requirements.txt





### **Step 2:** Train the AI Model

This project uses the phish\_dataset.csv file included in the repository. Ensure it is in the main project folder, then run the training script.



python model\_training.py





This script will use the dataset to generate the final model files (final\_phishing\_model.joblib and final\_model\_columns.joblib).



### **Step 3:** Run the Web Application

With the model trained, you can now start the Flask web server.



python app.py

