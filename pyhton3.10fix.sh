#!/bin/bash

# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies for building Python
sudo apt install -y build-essential libssl-dev zlib1g-dev \
  libbz2-dev libreadline-dev libsqlite3-dev curl git \
  libncursesw5-dev xz-utils tk-dev libxml2-dev \
  libxmlsec1-dev libffi-dev liblzma-dev

# Install pyenv
if [ ! -d "$HOME/.pyenv" ]; then
  curl https://pyenv.run | bash
fi

# Add pyenv to shell config if not already added
if ! grep -q 'pyenv init' ~/.bashrc; then
  echo 'export PATH="$HOME/.pyenv/bin:$PATH"' >> ~/.bashrc
  echo 'eval "$(pyenv init --path)"' >> ~/.bashrc
  echo 'eval "$(pyenv init -)"' >> ~/.bashrc
  echo 'eval "$(pyenv virtualenv-init -)"' >> ~/.bashrc
fi

# Reload shell
export PATH="$HOME/.pyenv/bin:$PATH"
eval "$(pyenv init --path)"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

# Install Python 3.10.14 with pyenv
pyenv install -s 3.10.14
pyenv global 3.10.14

# Go to Ryu project folder (adjust if needed)
cd ~/ryu || exit

# Create virtual environment
python -m venv venv310
source venv310/bin/activate

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install ryu eventlet
