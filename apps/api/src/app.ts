import { randomUUID } from "node:crypto";
import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import { pinoHttp } from "pino-http";
import type pg from "pg";
import type pino from "pino";
import { deviceAuth } from "./auth.js";
import { devicesRouter } from "./devices.js";
import { syncRouter } from "./sync.js";
export function createApp(options:{pool:pg.Pool;pepper:string;logger:pino.Logger}): express.Express {
 const app=express();app.disable("x-powered-by");app.set("trust proxy",1);app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'none'"],frameAncestors:["'none'"]}}}));
 app.use((req,res,next)=>{const supplied=req.header("x-request-id");const id=supplied?.slice(0,128) || randomUUID();res.setHeader("x-request-id",id);next();});
 app.use(pinoHttp({logger:options.logger}));
 app.use(express.json({limit:"2mb",type:"application/json"}));app.use(rateLimit({windowMs:15*60_000,limit:300,standardHeaders:"draft-8",legacyHeaders:false}));
 app.get("/health/live",(_req,res)=>res.json({status:"ok"}));app.get("/health/ready",async(_req,res)=>{try{await options.pool.query("SELECT 1");res.json({status:"ok"});}catch{res.status(503).json({status:"unavailable"});}});
 const authenticated=express.Router();authenticated.use((_req,res,next)=>{res.setHeader("cache-control","no-store");res.setHeader("pragma","no-cache");next();});authenticated.use(deviceAuth(options.pool,options.pepper));authenticated.get("/session",(req,res)=>res.json({deviceId:req.device!.deviceId,vaultId:req.device!.vaultId}));authenticated.use("/devices",devicesRouter(options.pool,options.pepper));authenticated.use("/sync",rateLimit({windowMs:60_000,limit:120,standardHeaders:"draft-8",legacyHeaders:false}),syncRouter(options.pool));app.use("/v1",authenticated);
 app.use((_req,res)=>res.status(404).json({error:"not_found"}));app.use((error:unknown,req:express.Request,res:express.Response,next:express.NextFunction)=>{void next;req.log.error({err:error},"request failed");res.status(500).json({error:"internal_error",requestId:res.getHeader("x-request-id")});});return app;
}
