const { EventEmitter } = require('events')
const process = require('process')

class HyperMultisigAbort extends EventEmitter {
  constructor(handler) {
    super()
    this.handler = handler
    this.aborted = false

    this._running = this._run()
    // This will always be awaited, but to avoid uncaughts in case it's not awaited in the same tick
    this._running.catch(() => {})
  }

  async _run() {
    const onSIGINT = () => {
      this.aborted = true
      this.emit('abort')
    }
    process.once('SIGINT', onSIGINT)
    try {
      // Tick so the user can register event listeners
      await new Promise((resolve) => queueMicrotask(resolve))
      return await this.handler(this)
    } finally {
      process.off('SIGINT', onSIGINT)
      if (this.aborted) process.exit(130) // exit code for Ctrl+C
    }
  }

  async done() {
    return await this._running
  }
}

module.exports = HyperMultisigAbort
