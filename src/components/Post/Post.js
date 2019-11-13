import React from 'react';
import PostHeader from './PostHeader/PostHeader'
import PostContent from './PostContent/PostContent';
import {Link, Redirect} from 'react-router-dom';

import {PostStore} from '../../data/resource/post';
import ErrorState from '../util/ErrorState/ErrorState';
import {FaExclamationTriangle} from 'react-icons/fa';
import styles from './Post.module.css'
import {Helmet} from "react-helmet";
import CommentsSection from "./CommentsSection/CommentsSection";

class Post extends React.Component {
    constructor(props) {
        super(props);
        this.onPostChange = this.onPostChange.bind(this);
        this.generateHeader = this.generateHeader.bind(this);

        this.state = {
            error: false,
            loading: true,
            post: {}
        }
    }

    onPostChange(post) {
        if (post.length === 0) {
            this.setState({
                error: true
            })
        }
        this.setState({
            post: post[0] || {},
            loading: false
        });
    }

    componentDidMount() {
        PostStore.getBySlug(this.props.match.params.slug)
            .then(this.onPostChange)
            .catch((e) => {
                console.error(e);
                this.setState({
                    error: true
                })
            });
    }

    generateHeader() {
        if (!this.state.loading) {
            console.log(this.state.post);
            return (
                <Helmet>
                    <title>{this.state.post.title}</title>
                    <meta name="author" content={this.state.post.author.username}/>
                    <meta name="robots" content="index,follow"/>
                    <meta name="directory" content="post"/>
                    <meta name="revised" content={this.state.post.updatedAt}/>
                    <meta name="og:title" content={this.state.post.title}/>
                    <meta name="og:type" content="article"/>
                    <meta name="og:url" content={'https://srikavin.me/blog/posts/' + this.state.post.slug}/>
                    <meta name="og:site_name" content='srikavin.me'/>
                </Helmet>
            )

        }
        return null;
    }

    render() {
        if (this.state.error) {
            return (
                <div className={styles['post-load-error']}>
                    <Redirect to="/404"/>

                    <ErrorState className={'header'} title={'This post could not be loaded'}
                                description={'There was an error attempting to load this post.'}
                                icon={<FaExclamationTriangle/>}
                                action={<Link to={'/'}>Go home</Link>}/>
                </div>
            )
        }
        return (
            <div>
                {this.generateHeader()}
                <PostHeader loading={this.state.loading}
                            className={styles.header}
                            author={this.state.post.author}
                            title={this.state.post.title}
                            tags={this.state.post.tags}
                            createdTime={this.state.post.createdAt}
                            modifiedTime={this.state.post.updatedAt}
                />
                <PostContent content={this.state.post.contents}/>
                {this.state.loading ? '' : <CommentsSection postId={this.state.post.id}/>}
            </div>
        )
    }
}

export default Post;