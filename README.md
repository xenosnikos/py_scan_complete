# **PyScan**

Flask based microservice responsible for running different types of network scans using opensource libraries and third party APIs.

## **Environment Setup:**

Ensure Python version 3.8+ is installed. 

Run command: `python --version` to see what version of python is running

Create a Python virtual environment

In the project directory, Run command: `python -m venv my_virtual_env` - my_virtual_env can be named as anything else.

To activate virtual environment, Run command: `source my_virtual_env/bin/activate` in Linux/Unix machines.

The command line should update and show the virtual environment name on the left.

### **Project dependencies:**

Run command: `pip install -r requirements.txt` to install all the project specific dependencies.

### **To run the project locally:**

`python main.py` should run the project

### **To run the project on a server:**
Run the project with gunicorn, enter `gunicorn -c gunicorn.conf.py main:app` along with required number of workers, threads, certificates and port binding.