# HARNESS_EDITOR

Attached Application will help you to edit and save changes to the harness_example.yaml file easily and quickly. Hence, reducing all the extra time and effort involved in testing redundantly. It's a interactive UI to configure your YAML and make things easier for you.

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install the following packages.


* ruamel.yaml

```bash
pip install ruamel.yaml
```

## Usage

```python
import ruamel.yaml

# create an object of YAML class
yaml = ruamel.yaml.YAML()

# Open yaml file in read mode and use load method.
# load method loads the yaml data in dictionary form.

with open('milestone21.yaml','r') as file:
  yaml_dict = yaml.load(file)

# dictionary is just a collection of key - value pairs.
yaml_dict['defaults']['dut'] = 'Your Device Under Test'

# Now dump the changes using dump method back into yaml file
with open('milestone21.yaml','w') as file:
  yaml.dump(yaml_dict, file)

```
* PyQt5

```bash
pip install PyQt5
```
## Usage

```python
# importing libraries
from PyQt5.QtWidgets import *
from PyQt5 import QtCore, QtGui
from PyQt5.QtGui import *
from PyQt5.QtCore import *
import sys


class Window(QMainWindow):

	def __init__(self):
		super().__init__()

		# setting title
		self.setWindowTitle("Python ")

		# setting geometry
		self.setGeometry(100, 100, 600, 400)

		# calling method
		self.UiComponents()

		# showing all the widgets
		self.show()

	# method for widgets
	def UiComponents(self):

		# creating a combo box widget
		combo_box = QComboBox(self)

		# setting geometry of combo box
		combo_box.setGeometry(200, 150, 120, 40)

		# adding items to combo box
		# adding One to the combobox
		combo_box.addItem("One")
		# adding Two to the combobox
		combo_box.addItem("Two")
		# adding Three to the combobox
		combo_box.addItem("Three")

# create pyqt5 app
App = QApplication(sys.argv)

# create the instance of our Window
window = Window()

# start the app
sys.exit(App.exec())

```


## Contributing
For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update whatever needs to be included.

Thank You.
