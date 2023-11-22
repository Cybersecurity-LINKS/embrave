# Build Documentation

## Install requirements with Python Virtual Environment
 - ```$ python3 -m venv .venv```
 - ```$ source .venv/bin/activate```
 - ```(.venv) $ pip3 install -r requirements.txt```

### Check installation
```
(.venv) $ sphinx-build --version
sphinx-build 4.0.2
```

## Build docs
- ```(.venv) $ sphinx-build -M html source/ build/```
- The docs will be available in the ```build``` directory
- Open in browser the file ```index.html```