const vscode = require("vscode");
const cp = require("child_process");

function activate(context) {
  const disposable = vscode.commands.registerCommand("mojo.runFile", () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showErrorMessage("Open a Mojo file before running.");
      return;
    }

    editor.document.save().then((saved) => {
      if (!saved) {
        vscode.window.showErrorMessage("Could not save the Mojo file.");
        return;
      }

      const executable = vscode.workspace
        .getConfiguration("mojo")
        .get("executable", "mojo");
      const terminal = vscode.window.createTerminal("Mojo");
      terminal.sendText(`${quote(executable)} run ${quote(editor.document.uri.fsPath)}`);
      terminal.show();
    });
  });

  context.subscriptions.push(disposable);
}

function quote(value) {
  return `"${String(value).replace(/(["$])/g, "`$1")}"`;
}

function deactivate() {}

module.exports = { activate, deactivate };
