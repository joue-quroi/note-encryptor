const {Plugin, Notice, Modal, Setting} = require('obsidian');

class PromptModal extends Modal {
  constructor(app) {
    super(app);
    this.password = '';
  }
  onOpen() {
    const {contentEl} = this;
    contentEl.classList.add('ingfy');
    contentEl.createEl('h1', {
      text: 'Open Database'
    });
    new Setting(contentEl).setName('Password').addText(text => {
      text.inputEl.type = 'password';
      text.inputEl.addEventListener('keypress', e => {
        if (e.key === 'Enter') {
          this.close();
        }
      });
      text.onChange(value => this.password = value);
      setTimeout(() => text.inputEl.focus(), 100);
    });

    const buttons = new Setting(contentEl);
    buttons.addButton(btn => btn.setButtonText('OK').setCta().onClick(() => {
      this.close();
    }));
  }
  onClose() {
    const {contentEl} = this;
    contentEl.empty();
  }
}

class CryptoFactory {
  constructor() {
    this.vectorSize = 16;
    this.saltSize = 16;
    this.iterations = 262144;
  }
  convertArrayToString(bytes) {
    let result = '';
    for (let i = 0; i < bytes.length; i++) {
      result += String.fromCharCode(bytes[i]);
    }
    return result;
  }
  convertStringToArray(str) {
    const result = [];
    for (let i = 0; i < str.length; i++) {
      result.push(str.charCodeAt(i));
    }
    return new Uint8Array(result);
  }
  async deriveKey(password, salt) {
    const utf8Encoder = new TextEncoder();
    const keyData = utf8Encoder.encode(password);
    const key = await crypto.subtle.importKey('raw', keyData, {
      name: 'PBKDF2'
    }, false, ['deriveKey']);
    const privateKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        hash: {
          name: 'SHA-512'
        },
        salt,
        iterations: this.iterations
      },
      key,
      {
        name: 'AES-GCM',
        length: 256
      },
      false,
      ['encrypt', 'decrypt']
    );
    return privateKey;
  }
  async encryptToBytes(text, password) {
    const salt = crypto.getRandomValues(new Uint8Array(this.saltSize));
    const key = await this.deriveKey(password, salt);
    const utf8Encoder = new TextEncoder();
    const textBytesToEncrypt = utf8Encoder.encode(text);
    const vector = crypto.getRandomValues(new Uint8Array(this.vectorSize));
    const encryptedBytes = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: vector
        },
        key,
        textBytesToEncrypt
      )
    );
    const finalBytes = new Uint8Array(vector.byteLength + salt.byteLength + encryptedBytes.byteLength);
    finalBytes.set(vector, 0);
    finalBytes.set(salt, vector.byteLength);
    finalBytes.set(encryptedBytes, vector.byteLength + salt.byteLength);
    return finalBytes;
  }
  async encryptToBase64(text, password) {
    const finalBytes = await this.encryptToBytes(text, password);
    const base64Text = btoa(this.convertArrayToString(finalBytes));
    return base64Text;
  }
  async decryptFromBytes(encryptedBytes, password) {
    let offset;
    let nextOffset;
    offset = 0;
    nextOffset = offset + this.vectorSize;
    const vector = encryptedBytes.slice(offset, nextOffset);
    offset = nextOffset;
    nextOffset = offset + this.saltSize;
    const salt = encryptedBytes.slice(offset, nextOffset);
    offset = nextOffset;
    nextOffset = void 0;
    const encryptedTextBytes = encryptedBytes.slice(offset);
    const key = await this.deriveKey(password, salt);
    const decryptedBytes = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: vector
      },
      key,
      encryptedTextBytes
    );
    const utf8Decoder = new TextDecoder();
    const decryptedText = utf8Decoder.decode(decryptedBytes);
    return decryptedText;
  }
  async decryptFromBase64(base64Encoded, password) {
    const bytesToDecode = this.convertStringToArray(atob(base64Encoded));
    return await this.decryptFromBytes(bytesToDecode, password);
  }
}

class EncryptionPlugin extends Plugin {
  onload() {
    const crypto = new CryptoFactory();
    const prefix = 'enc-v0-';
    const extension = 'enc';

    // register files as markdown
    this.registerExtensions([extension], 'markdown');

    // make sure to have a single prompt
    const ask = () => ask.password ? Promise.resolve(ask.password) : new Promise(resolve => {
      if (ask.busy) {
        return ask.resolves.add(resolve);
      }
      ask.busy = true;

      const m = new PromptModal(this.app);
      m.open();
      m.onClose = () => {
        ask.password = m.password;
        resolve(m.password);
        ask.busy = false;

        for (const resolve of ask.resolves.values()) {
          resolve(m.password);
        }
        ask.resolves.clear();
      };
    });
    ask.busy = false;
    ask.resolves = new Set();

    // overwrite "write" for ".md" and ".extension"
    this.app.vault.adapter.write = new Proxy(this.app.vault.adapter.write, {
      apply(target, self, args) {
        const [path, content] = args;

        if (content && path.includes('.' + extension)) {
          console.info('encrypting', path);

          ask().then(password => crypto.encryptToBase64(content, password).then(encrypted => {
            args[1] = prefix + encrypted;
            return Reflect.apply(target, self, args);
          }).catch(e => {
            new Notice('\u274C Cannot save as encrypted: ' + e.message);

            args[1] = 'Error: ' + e.message + '\n\n' + content;
            return Reflect.apply(target, self, args);
          }));
        }
        else {
          return Reflect.apply(target, self, args);
        }
      }
    });

    // overwrite "read"
    this.app.vault.adapter.read = new Proxy(this.app.vault.adapter.read, {
      apply(target, self, args) {
        const [path] = args;

        if (path.includes('.' + extension)) {
          return Reflect.apply(target, self, args).then(content => {
            if (content.startsWith(prefix)) {
              console.info('decrypting', path);

              return ask().then(password => {
                return crypto.decryptFromBase64(content.slice(prefix.length), password).catch(e => {
                  new Notice('\u274C Cannot decrypt note. Reopen to fix: ' + e.message);
                  ask.password = '';

                  return content;
                });
              });
            }
            return content;
          });
        }
        else {
          return Reflect.apply(target, self, args);
        }
      }
    });

    // pretend ".enc" to be ".md" for search
    this.app.vault.getFiles = new Proxy(this.app.vault.getFiles, {
      apply(target, self, args) {
        const {stack} = new Error();
        const r = Reflect.apply(target, self, args);
        if (stack.includes('.startSearch')) {
          for (const file of r) {
            if (file.extension === extension) {
              file.extension = 'md';
            }
          }
          return r;
        }
        else {
          return r;
        }
      }
    });

    // change format from md to enc for new file creation
    this.app.fileManager.fileParentCreatorByType[extension] = this.app.fileManager.fileParentCreatorByType.md;
    this.app.fileManager.createNewFile = new Proxy(this.app.fileManager.createNewFile, {
      apply(target, self, args) {
        if (args[2] === 'md') {
          args[2] = extension;
        }
        return Reflect.apply(target, self, args);
      }
    });
  }
}

module.exports = EncryptionPlugin;
