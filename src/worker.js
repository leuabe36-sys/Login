} catch (err) {
      return withCors(json({ error: "Something went wrong." }, 500));
    }

    return withCors(json({ error: "Not found." }, 404));
