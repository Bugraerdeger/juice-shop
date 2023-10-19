import { NextFunction, Request, Response } from 'express'
import fs from 'fs'
import yaml from 'js-yaml'
import { getCodeChallenges } from '../lib/codingChallenges'
import * as accuracy from '../lib/accuracy'
import * as utils from '../lib/utils'
import challengeUtils from '../lib/challengeUtils'

interface SnippetRequestBody {
  challenge: string
}

interface VerdictRequestBody {
  selectedLines: number[]
  key: string
}

const setStatusCode = (error: any) => {
  switch (error.name) {
    case 'BrokenBoundary':
      return 422
    default:
      return 200
  }
}

const retrieveCodeSnippet = async (challengeKey: string) => {
  const codeChallenges = await getCodeChallenges()
  return codeChallenges.get(challengeKey) || null
}

export const serveCodeSnippet = async (req: Request<SnippetRequestBody>, res: Response, next: NextFunction) => {
  try {
    const snippetData = await retrieveCodeSnippet(req.params.challenge)
    if (!snippetData) {
      res.status(404).json({ status: 'error', error: `No code challenge for challenge key: ${req.params.challenge}` })
      return
    }
    res.status(200).json({ snippet: snippetData.snippet })
  } catch (error) {
    const statusCode = setStatusCode(error)
    res.status(statusCode).json({ status: 'error', error: utils.getErrorMessage(error) })
  }
}

const retrieveChallengesWithCodeSnippet = async () => {
  const codeChallenges = await getCodeChallenges()
  return Array.from(codeChallenges.keys())
}

export const serveChallengesWithCodeSnippet = async (req: Request, res: Response, next: NextFunction) => {
  const codingChallenges = await retrieveChallengesWithCodeSnippet()
  res.json({ challenges: codingChallenges })
}

const getVerdict = (vulnLines: number[], neutralLines: number[], selectedLines: number[]) => {
  if (!selectedLines) return false
  if (vulnLines.length > selectedLines.length) return false
  if (!vulnLines.every(e => selectedLines.includes(e))) return false
  const okLines = [...vulnLines, ...neutralLines]
  const notOkLines = selectedLines.filter(x => !okLines.includes(x))
  return notOkLines.length === 0
}

export const checkVulnLines = async (req: Request<Record<string, unknown>, Record<string, unknown>, VerdictRequestBody>, res: Response, next: NextFunction) => {
  const key = req.body.key
  let snippetData
  try {
    snippetData = await retrieveCodeSnippet(key)
    if (!snippetData) {
      res.status(404).json({ status: 'error', error: `No code challenge for challenge key: ${key}` })
      return
    }
  } catch (error) {
    const statusCode = setStatusCode(error)
    res.status(statusCode).json({ status: 'error', error: utils.getErrorMessage(error) })
    return
  }
  const { vulnLines, neutralLines } = snippetData
  const selectedLines = req.body.selectedLines
  const verdict = getVerdict(vulnLines, neutralLines, selectedLines)
  let hint
  const filePath = `./data/static/codefixes/${key}.info.yml`
  if (fs.existsSync(filePath)) {
    const codingChallengeInfos = yaml.load(fs.readFileSync(filePath, 'utf8'))
    if (codingChallengeInfos?.hints) {
      const findItAttempts = accuracy.getFindItAttempts(key)
      if (findItAttempts > codingChallengeInfos.hints.length) {
        if (vulnLines.length === 1) {
          hint = res.__(`Line ${vulnLines[0]} is responsible for this vulnerability or security flaw. Select it and submit to proceed.`)
        } else {
          hint = res.__(`Lines ${vulnLines.join(', ')} are responsible for this vulnerability or security flaw. Select them and submit to proceed.`)
        }
      } else {
        const nextHint = codingChallengeInfos.hints[findItAttempts - 1]
        if (nextHint) hint = res.__(nextHint)
      }
    }
  }
  if (verdict) {
    await challengeUtils.solveFindIt(key)
    res.status(200).json({
      verdict: true
    })
  } else {
    accuracy.storeFindItVerdict(key, false)
    res.status(200).json({
      verdict: false,
      hint
    })
  }
}
