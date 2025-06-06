package org.multipaz.mdoc.transport

/**
 * Thrown if an unrecoverable error occurs.
 */
class MdocTransportException : Exception {
    /**
     * Construct a new exception.
     */
    constructor()

    /**
     * Construct a new exception.
     *
     */
    constructor(message: String) : super(message)

    /**
     * Construct a new exception.
     *
     * @param message the message.
     * @param cause the cause.
     */
    constructor(
        message: String,
        cause: Throwable
    ) : super(message, cause)

    /**
     * Construct a new exception.
     *
     * @param cause the cause.
     */
    constructor(cause: Throwable) : super(cause)
}