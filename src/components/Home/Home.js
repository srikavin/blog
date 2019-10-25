import React, {Component} from 'react';
import PostPreviews from '../PostPreviews/PostPreviews';
import {Helmet} from "react-helmet";

class Home extends Component {
    render() {

        return (
            <div>
                <Helmet>
                    <title>Blog</title>
                </Helmet>
                <PostPreviews/>
            </div>
        );
    }
}

Home.propTypes = {};

export default Home;