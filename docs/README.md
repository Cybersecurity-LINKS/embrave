# Build Documentation

## Install requirements with Python Virtual Environment
 - ```$ python3 -m venv .venv```
 - ```$ source .venv/bin/activate```
 - ```(.venv) $ pip3 install -r requirements.txt```

### Check installation
```
(.venv) $ sphinx-build --version
sphinx-build 7.2.6
```

## Build docs
- ```(.venv) $ make html```
- The docs will be available in the ```build``` directory
- Open in browser the file ```index.html```