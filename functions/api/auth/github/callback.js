async function signJwt(payload, secret) {
   const header = { alg: "HS256", typ: "JWT" }
   const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_")
   const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_")
   const tokenInput = `${encodedHeader}.${encodedPayload}`
   const encoder = new TextEncoder()
   const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
   )
   const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(tokenInput))
   const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_")
   return `${tokenInput}.${encodedSignature}`
}

export async function onRequest(context) {
   const { request, env } = context
   const url = new URL(request.url)
   const code = url.searchParams.get("code")
   const stateParam = url.searchParams.get("state")

   if (!code || !stateParam) {
      return new Response("Kode otorisasi atau state tidak valid", { status: 400 })
   }

   try {
      const stateData = JSON.parse(atob(stateParam))
      const targetRedirect = stateData.redirect_to

      const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
         method: "POST",
         headers: {
            "Content-Type": "application/json",
            "Accept": "application/json"
         },
         body: JSON.stringify({
            client_id: env.GITHUB_CLIENT_ID,
            client_secret: env.GITHUB_CLIENT_SECRET,
            code: code
         })
      })
      const tokenData = await tokenResponse.json()

      if (tokenData.error) {
         return new Response(`OAuth Error: ${tokenData.error_description}`, { status: 400 })
      }

      const userResponse = await fetch("https://api.github.com/user", {
         headers: {
            "Authorization": `token ${tokenData.access_token}`,
            "User-Agent": "neoxr-oss-oauth-gateway"
         }
      })
      const userData = await userResponse.json()

      const payload = {
         id: userData.id,
         username: userData.login,
         email: userData.email,
         provider: "github",
         exp: Math.floor(Date.now() / 1000) + (2 * 60 * 60)
      }

      const jwt = await signJwt(payload, env.JWT_SECRET)

      const finalRedirectUrl = new URL(targetRedirect)
      finalRedirectUrl.searchParams.set("token", jwt)

      return Response.redirect(finalRedirectUrl.toString(), 302)
   } catch (error) {
      return new Response(`Terjadi kesalahan: ${error.message}`, { status: 500 })
   }
}