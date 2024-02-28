# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'lemon'
copyright = '2023, Alessio Claudio, Enrico Bravi'
author = 'Alessio Claudio, Enrico Bravi'
release = '0.1'
version = '0.1'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = []

templates_path = ['_templates']
exclude_patterns = []



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']
html_show_sourcelink = False
html_context = {
    "display_github": True, # Integrate GitHub
    "github_user": "Cybersecurity-LINKS", # Username
    "github_repo": "lemon", # Repo name
    "github_version": "main", # Version
    "conf_py_path": "/docs/source/", # Path in the checkout to the docs root
}
