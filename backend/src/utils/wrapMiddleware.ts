import { Request, Response, NextFunction, RequestHandler } from 'express';

export const wrapMiddleware = (

    fn: (req: Request, res: Response, next: NextFunction) => any
): RequestHandler => {
    return (req, res, next) => {
        const maybePromise = fn(req, res, next);
        if (maybePromise instanceof Promise) {
            maybePromise.catch(next);
        }
    }
}
