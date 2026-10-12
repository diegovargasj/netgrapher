// Undo/redo for annotation edits. Each command is a batch of patches plus its inverse.

function invert(current, patch) {
  const inverse = {};
  for (const key of Object.keys(patch)) inverse[key] = key in current ? current[key] : null;
  return inverse;
}

export class History {
  constructor(apply, onChange) {
    this.apply = apply; // async (items) => void
    this.onChange = onChange;
    this.undoStack = [];
    this.redoStack = [];
  }

  async do(items, annotations) {
    if (!items.length) return;
    const inverse = items.map(({ id, patch }) => ({ id, patch: invert(annotations[id] || {}, patch) }));
    await this.apply(items);
    this.undoStack.push({ items, inverse });
    this.redoStack = [];
    this.onChange();
  }

  async undo() {
    const command = this.undoStack.pop();
    if (!command) return;
    await this.apply(command.inverse);
    this.redoStack.push(command);
    this.onChange();
  }

  async redo() {
    const command = this.redoStack.pop();
    if (!command) return;
    await this.apply(command.items);
    this.undoStack.push(command);
    this.onChange();
  }

  /** Follow entities that were merged into others (aliases) during a live run. */
  renameIds(aliases) {
    const rename = (items) => items.forEach((item) => { item.id = aliases[item.id] || item.id; });
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
