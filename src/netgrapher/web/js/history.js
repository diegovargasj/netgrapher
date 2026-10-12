// Undo/redo. A command is { redo, undo } async thunks. Annotation commands also carry their
// { items, inverse } patch arrays so ids can be rewritten when entities merge during a live run.

export function invert(current, patch) {
  const inverse = {};
  for (const key of Object.keys(patch)) inverse[key] = key in current ? current[key] : null;
  return inverse;
}

export class History {
  constructor(onChange) {
    this.onChange = onChange;
    this.undoStack = [];
    this.redoStack = [];
  }

  async push(command) {
    await command.redo();
    this.undoStack.push(command);
    this.redoStack = [];
    this.onChange();
  }

  async undo() {
    const command = this.undoStack.pop();
    if (!command) return;
    await command.undo();
    this.redoStack.push(command);
    this.onChange();
  }

  async redo() {
    const command = this.redoStack.pop();
    if (!command) return;
    await command.redo();
    this.undoStack.push(command);
    this.onChange();
  }

  /** Follow entities merged into others (aliases) during a live run, in annotation commands. */
  renameIds(aliases) {
    const rename = (items) => items?.forEach((item) => { item.id = aliases[item.id] || item.id; });
    for (const command of [...this.undoStack, ...this.redoStack]) {
      rename(command.items);
      rename(command.inverse);
    }
  }

  clear() {
    this.undoStack = [];
    this.redoStack = [];
    this.onChange();
  }

  get canUndo() { return this.undoStack.length > 0; }
  get canRedo() { return this.redoStack.length > 0; }
}
