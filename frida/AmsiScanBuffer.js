{
  onEnter: function(log, args, state) {
    log('AmsiScanBuffer()');
    log('|- amsiContext: ' + args[0]);
    log('|- buffer: ' + Memory.readUtf16String(args[1]));
    log('|- length: ' + args[2]);
    log('|- contentName ' + args[3]);
    log('|- amsiSession ' + args[4]);
    log('|- result ' + args[5] + "\n");
    this.resultPointer = args[5];
  },

  onLeave: function(log, retval, state) {
    log('[*] AmsiScanBuffer() Exit');
    resultPointer = this.resultPointer;
    log('|- Result value is: ' + Memory.readUShort(resultPointer) + "\n");
  }
}
