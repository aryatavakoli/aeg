#!/bin/bash
sudo apt update
sudo apt install build-essential python3 python3-pip libffi-dev libssl-dev -y

sudo -H pip3 install --upgrade pip
sudo pip3 install virtualenv virtualenvwrapper

printf '\n%s\n%s\n%s' '# virtualenv' 'export WORKON_HOME=~/virtualenvs' 'source /usr/local/bin/virtualenvwrapper.sh' >> ~/.bashrc

#https://virtualenvwrapper.readthedocs.io/en/latest/
export WORKON_HOME=~/virtualenvs
mkdir -p $WORKON_HOME

#https://virtualenvwrapper.readthedocs.io/en/latest/install.html#python-interpreter-virtualenv-and-path
export VIRTUALENVWRAPPER_PYTHON=/usr/bin/python3
source /usr/local/bin/virtualenvwrapper.sh

#https://virtualenvwrapper.readthedocs.io/en/latest/command_ref.html
mkvirtualenv --python=$VIRTUALENVWRAPPER_PYTHON aeg
workon aeg

# For angr
# sudo -H pip3 install pip3 install one_gadget cffi
# sudo -H pip3 install angr IPython r2pipe pwn timeout_decorator

# For Manticore
# sudo -H pip3 install manticore r2pipe timeout_decorator pwn

#Installs r2
git clone https://github.com/radare/radare2.git
sudo ./radare2/sys/install.sh

echo "####################"
echo "Soruce bashfile"
echo "run: workon aeg"